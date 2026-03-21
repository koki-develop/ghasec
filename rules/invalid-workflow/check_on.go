package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkOnEventFilters(entry *ast.MappingValueNode) []*diagnostic.Error {
	filterMapping, ok := entry.Value.(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	present := make(map[string]*token.Token)
	for _, filterEntry := range filterMapping.Values {
		key := filterEntry.Key.GetToken().Value
		present[key] = filterEntry.Key.GetToken()
	}

	for _, pair := range filterConflicts {
		a, b := pair[0], pair[1]
		if present[a] != nil && present[b] != nil {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("%q and %q are mutually exclusive", a, b),
				Markers: []*token.Token{present[a], present[b]},
			})
		}
	}

	return errs
}

func checkOnSchedule(entry *ast.MappingValueNode) []*diagnostic.Error {
	seq, ok := entry.Value.(*ast.SequenceNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   entry.Value.GetToken(),
			Message: fmt.Sprintf("\"schedule\" must be a sequence, but got %s", entry.Value.Type()),
		}}
	}

	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		itemMapping, ok := item.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:   item.GetToken(),
				Message: fmt.Sprintf("\"schedule\" elements must be mappings, but got %s", item.Type()),
			})
			continue
		}
		cronKV := workflow.Mapping{MappingNode: itemMapping}.FindKey("cron")
		if cronKV == nil {
			errs = append(errs, &diagnostic.Error{
				Token:   item.GetToken(),
				Message: "\"cron\" is required",
			})
		}
	}
	return errs
}

func checkOnWorkflowDispatch(entry *ast.MappingValueNode) []*diagnostic.Error {
	if _, ok := entry.Value.(*ast.NullNode); ok {
		return nil // workflow_dispatch: (no value) is valid
	}
	dispatchMapping, ok := entry.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   entry.Value.GetToken(),
			Message: fmt.Sprintf("\"workflow_dispatch\" must be a mapping, but got %s", entry.Value.Type()),
		}}
	}

	var errs []*diagnostic.Error
	for _, dispatchEntry := range dispatchMapping.Values {
		key := dispatchEntry.Key.GetToken().Value
		if !knownWorkflowDispatchKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   dispatchEntry.Key.GetToken(),
				Message: fmt.Sprintf("\"workflow_dispatch\" has unknown key %q", key),
			})
		}
	}

	// Validate input entry keys
	inputsKV := workflow.Mapping{MappingNode: dispatchMapping}.FindKey("inputs")
	if inputsKV != nil {
		inputsMapping, ok := inputsKV.Value.(*ast.MappingNode)
		if ok {
			for _, inputEntry := range inputsMapping.Values {
				inputValueMapping, ok := inputEntry.Value.(*ast.MappingNode)
				if !ok {
					if _, isNull := inputEntry.Value.(*ast.NullNode); !isNull {
						errs = append(errs, &diagnostic.Error{
							Token:   inputEntry.Value.GetToken(),
							Message: fmt.Sprintf("input %q must be a mapping, but got %s", inputEntry.Key.GetToken().Value, inputEntry.Value.Type()),
						})
					}
					continue
				}
				for _, inputProp := range inputValueMapping.Values {
					propKey := inputProp.Key.GetToken().Value
					if !knownWorkflowDispatchInputKeys[propKey] {
						errs = append(errs, &diagnostic.Error{
							Token:   inputProp.Key.GetToken(),
							Message: fmt.Sprintf("input %q has unknown key %q", inputEntry.Key.GetToken().Value, propKey),
						})
					}
				}
			}
		}
	}

	return errs
}
