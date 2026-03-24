package invalidworkflow

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-workflow"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	fileStart := mapping.FirstToken()
	genErrs := rules.Dedup(validateWorkflow(mapping))
	// Fix error tokens BEFORE sorting
	for i := range genErrs {
		// Top-level required errors should point to file start
		if genErrs[i].Kind == rules.KindRequiredKey && genErrs[i].Path == "" {
			genErrs[i].Token = fileStart
		}
		// D1: Nested required errors now get correct tokens from the emitter
		// (parentKeyTokenExpr). No need to override here.
	}
	for _, ve := range rules.SortRequiredFirst(genErrs) {
		errs = append(errs, toDiagnostic(ve))
	}

	// Hand-written extensions (run AFTER generated validation, never replace it).

	// B1: Filter conflicts (branches/branches-ignore, tags/tags-ignore, paths/paths-ignore)
	errs = append(errs, checkOnFilterConflicts(mapping.Mapping)...)

	// V6: Cron expression validation
	errs = append(errs, checkCronExpressions(mapping.Mapping)...)

	// V7: Choice default must be in options
	errs = append(errs, checkChoiceDefaultInOptions(mapping.Mapping)...)

	// V8: Filter negation requires positive pattern
	errs = append(errs, checkFilterNegationPatterns(mapping.Mapping)...)

	// B2: Job-level mutual exclusion (runs-on/uses, uses/steps)
	// B3: Step-level mutual exclusion (uses/run)
	// C1: Remote action ref format
	// V1: Step ID uniqueness
	// V2: Needs reference validity and cycle detection
	if kv := mapping.FindKey("jobs"); kv != nil {
		if jobsMapping, ok := rules.UnwrapNode(kv.Value).(*ast.MappingNode); ok {
			errs = append(errs, checkJobExtensions(jobsMapping)...)
			errs = append(errs, checkNeedsValidity(jobsMapping)...)
		}
	}

	// V9: Expression position validation
	errs = append(errs, checkExpressionPositions(mapping.Mapping)...)

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
			// Multiple alternatives (e.g. "runs-on" or "uses")
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
		} else if isPermissionsScopePath(ve.Path) {
			msg = fmt.Sprintf("\"permissions\" scope %q must be a %s, but got %s", ve.Key, rules.JoinOr(ve.Allowed), ve.Got)
		} else {
			msg = fmt.Sprintf("%q must be a %s, but got %s", ve.Key, rules.JoinOr(ve.Allowed), ve.Got)
		}
	case rules.KindInvalidEnum:
		if ve.Parent == "on" && ve.Context == "event" {
			msg = fmt.Sprintf("\"on\" has unknown event %q", ve.Got)
		} else if isOnEventPath(ve.Path) {
			msg = fmt.Sprintf("\"on\" has unknown event %q", ve.Got)
		} else if isPermissionsScopePath(ve.Path) {
			msg = fmt.Sprintf("\"permissions\" scope %q must be %s, but got %q", ve.Key, joinQuoted(ve.Allowed), ve.Got)
		} else if ve.Path == "permissions" && ve.Key == "permissions" {
			msg = fmt.Sprintf("\"permissions\" must be %s, but got %q", joinQuoted(ve.Allowed), ve.Got)
		} else if ve.Parent != "" && ve.Context != "" {
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

// joinQuoted formats allowed values as quoted alternatives: "a", "b", or "c".
func joinQuoted(allowed []string) string {
	if len(allowed) == 0 {
		return "(none)"
	}
	quoted := make([]string, len(allowed))
	for i, a := range allowed {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	if len(quoted) <= 2 {
		return strings.Join(quoted, " or ")
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + ", or " + quoted[len(quoted)-1]
}

// isPermissionsScopePath checks if a path refers to a specific permission scope
// (e.g. "permissions.contents" or "jobs.*.permissions.contents").
func isPermissionsScopePath(path string) bool {
	parts := strings.Split(path, ".")
	for i, p := range parts {
		if p == "permissions" && i+1 < len(parts) {
			return true
		}
	}
	return false
}

// isOnEventPath checks if a path refers to a direct child of "on"
// (e.g. "on.push", "on.*") but NOT deeper descendants like "on.workflow_call.inputs.*.type".
func isOnEventPath(path string) bool {
	if !strings.HasPrefix(path, "on.") {
		return false
	}
	// Count dots after "on." — if more than one, it's a deep descendant
	rest := strings.TrimPrefix(path, "on.")
	return !strings.Contains(rest, ".")
}
