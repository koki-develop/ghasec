package invalidaction

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-action"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	fileStart := mapping.FirstToken()
	genErrs := rules.Dedup(validateAction(mapping))
	// Fix error tokens BEFORE sorting
	for i := range genErrs {
		// Top-level required errors should point to file start
		if genErrs[i].Kind == rules.KindRequiredKey && genErrs[i].Path == "" {
			genErrs[i].Token = fileStart
		}
	}
	for _, ve := range rules.SortRequiredFirst(genErrs) {
		errs = append(errs, toDiagnostic(ve))
	}

	// Hand-written extensions (run AFTER generated validation, never replace it).
	// V1: Step ID uniqueness in composite steps
	// V3: shell/working-directory require run in composite steps
	// C1: Remote action ref in composite steps
	// B3: Step mutual exclusion in composite steps
	if runsKV := mapping.FindKey("runs"); runsKV != nil {
		if runsMapping, ok := rules.UnwrapNode(runsKV.Value).(*ast.MappingNode); ok {
			m := workflow.Mapping{MappingNode: runsMapping}
			if stepsKV := m.FindKey("steps"); stepsKV != nil {
				if seq, ok := rules.UnwrapNode(stepsKV.Value).(*ast.SequenceNode); ok {
					errs = append(errs, checkStepIDUniqueness(seq)...)
					errs = append(errs, checkCompositeStepExtensions(seq)...)
				}
			}
		}
	}
	return errs
}

// V1: Step ID uniqueness within composite action steps.
func checkStepIDUniqueness(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	seen := make(map[string]*token.Token)
	for _, item := range seq.Values {
		stepMapping, ok := rules.UnwrapNode(item).(*ast.MappingNode)
		if !ok {
			continue
		}
		step := workflow.Mapping{MappingNode: stepMapping}
		idKV := step.FindKey("id")
		if idKV == nil {
			continue
		}
		idValue := rules.StringValue(idKV.Value)
		if idValue == "" || rules.IsExpressionNode(idKV.Value) {
			continue
		}
		if firstToken, exists := seen[idValue]; exists {
			errs = append(errs, &diagnostic.Error{
				Token:   idKV.Value.GetToken(),
				Message: fmt.Sprintf("step id %q must be unique", idValue),
				Markers: []*token.Token{firstToken},
			})
		} else {
			seen[idValue] = idKV.Value.GetToken()
		}
	}
	return errs
}

// checkCompositeStepExtensions runs hand-written checks on composite action steps.
func checkCompositeStepExtensions(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		stepMapping, ok := rules.UnwrapNode(item).(*ast.MappingNode)
		if !ok {
			continue
		}
		step := workflow.Mapping{MappingNode: stepMapping}

		// B3: Step mutual exclusion
		usesKV := step.FindKey("uses")
		runKV := step.FindKey("run")
		if usesKV != nil && runKV != nil {
			firstToken := usesKV.Key.GetToken()
			secondToken := runKV.Key.GetToken()
			if secondToken.Position.Offset < firstToken.Position.Offset {
				firstToken, secondToken = secondToken, firstToken
			}
			errs = append(errs, &diagnostic.Error{
				Token:   firstToken,
				Message: "\"uses\" and \"run\" are mutually exclusive",
				Markers: []*token.Token{secondToken},
			})
		}

		// V3: shell/working-directory require run (action composite steps use oneOf,
		// not the dependencies keyword, so this must be hand-written)
		if usesKV != nil && runKV == nil {
			for _, depKey := range []string{"shell", "working-directory"} {
				if depKV := step.FindKey(depKey); depKV != nil {
					errs = append(errs, &diagnostic.Error{
						Token:   depKV.Key.GetToken(),
						Message: fmt.Sprintf("%q must be used with %q", depKey, "run"),
					})
				}
			}
		}

		// C1: Remote action ref format
		if usesKV != nil {
			stepW := workflow.StepMapping{Mapping: step}
			ref, ok := stepW.Uses()
			if ok && !ref.IsLocal() && !ref.IsDocker() && ref.Ref() == "" {
				errs = append(errs, &diagnostic.Error{
					Token:   ref.Token(),
					Message: fmt.Sprintf("%q must have a ref (e.g. %s@<ref>)", ref.String(), ref.String()),
				})
			}
		}
	}
	return errs
}

// toDiagnostic converts a generated ValidationError to a diagnostic.Error,
// producing messages that match the desired format.
func toDiagnostic(ve rules.ValidationError) *diagnostic.Error {
	var msg string
	switch ve.Kind {
	case rules.KindUnknownKey:
		if ve.Parent != "" && ve.Context != "" {
			msg = fmt.Sprintf("%q has unknown %s %q", ve.Parent, ve.Context, ve.Key)
		} else if ve.Parent != "" {
			msg = fmt.Sprintf("%q has unknown key %q", ve.Parent, ve.Key)
		} else {
			msg = fmt.Sprintf("unknown key %q", ve.Key)
		}
	case rules.KindRequiredKey:
		if len(ve.Allowed) > 1 {
			quoted := make([]string, len(ve.Allowed))
			for i, a := range ve.Allowed {
				quoted[i] = fmt.Sprintf("%q", a)
			}
			msg = fmt.Sprintf("%s is required", strings.Join(quoted, " or "))
		} else {
			msg = fmt.Sprintf("%q is required", ve.Key)
		}
	case rules.KindTypeMismatch:
		if ve.Got == "null" {
			if before, ok := strings.CutSuffix(ve.Key, "[]"); ok {
				msg = fmt.Sprintf("%q element must not be empty", before)
			} else {
				msg = fmt.Sprintf("%q must not be empty", ve.Key)
			}
		} else if before, ok := strings.CutSuffix(ve.Key, "[]"); ok {
			msg = fmt.Sprintf("%q elements must be %s, but got %s", before, rules.JoinPlural(ve.Allowed), ve.Got)
		} else {
			msg = fmt.Sprintf("%q must be a %s, but got %s", ve.Key, rules.JoinOr(ve.Allowed), ve.Got)
		}
	case rules.KindInvalidEnum:
		if ve.Parent != "" && ve.Context != "" {
			msg = fmt.Sprintf("%q has unknown %s %q", ve.Parent, ve.Context, ve.Got)
		} else {
			msg = fmt.Sprintf("%q has unknown value %q", ve.Key, ve.Got)
		}
	case rules.KindMinItems:
		msg = fmt.Sprintf("%q must not be empty", ve.Key)
	case rules.KindDependency:
		msg = fmt.Sprintf("%q must be used with %q", ve.Key, ve.Got)
	default:
		msg = fmt.Sprintf("validation error on %q: %s", ve.Key, ve.Got)
	}
	return &diagnostic.Error{Token: ve.Token, Message: msg}
}
