package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkStepEntries(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		stepMapping, ok := item.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:   item.GetToken(),
				Message: fmt.Sprintf("step must be a mapping, but got %s", item.Type()),
			})
			continue
		}
		errs = append(errs, checkStep(workflow.Mapping{MappingNode: stepMapping})...)
	}
	return errs
}

func checkStep(step workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	usesKV := step.FindKey("uses")
	runKV := step.FindKey("run")

	hasUses := usesKV != nil
	hasRun := runKV != nil

	if !hasUses && !hasRun {
		errs = append(errs, &diagnostic.Error{
			Token:   step.GetToken(),
			Message: "\"uses\" or \"run\" is required",
		})
	}
	if hasUses && hasRun {
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

	if hasUses {
		stepMapping := workflow.StepMapping{Mapping: step}
		ref, ok := stepMapping.Uses()
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:   usesKV.Value.GetToken(),
				Message: fmt.Sprintf("\"uses\" must be a string, but got %s", usesKV.Value.Type()),
			})
		} else if !ref.IsLocal() && !ref.IsDocker() && ref.Ref() == "" {
			errs = append(errs, &diagnostic.Error{
				Token:   ref.Token(),
				Message: fmt.Sprintf("%q must have a ref (e.g. %s@<ref>)", ref.String(), ref.String()),
			})
		}
	}

	for _, entry := range step.Values {
		key := entry.Key.GetToken().Value
		if !knownStepKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("unknown key %q", key),
			})
		}
	}

	return errs
}
