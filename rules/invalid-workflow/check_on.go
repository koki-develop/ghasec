package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkOn(mapping workflow.Mapping, fileStart *token.Token) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return []*diagnostic.Error{{
			Token:   fileStart,
			Message: "\"on\" is required",
		}}
	}

	switch v := kv.Value.(type) {
	case *ast.StringNode:
		return checkOnEventName(v.Value, v.GetToken())
	case *ast.LiteralNode:
		return checkOnEventName(v.Value.Value, v.GetToken())
	case *ast.SequenceNode:
		return checkOnSequence(v)
	case *ast.MappingNode:
		return checkOnMapping(v)
	default:
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"on\" must be a string, sequence, or mapping, but got %s", kv.Value.Type()),
		}}
	}
}

func checkOnEventName(name string, tk *token.Token) []*diagnostic.Error {
	if knownOnEvents[name] {
		return nil
	}
	return []*diagnostic.Error{{
		Token:   tk,
		Message: fmt.Sprintf("\"on\" has unknown event %q", name),
	}}
}

func checkOnSequence(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		name := stringValue(item)
		if name == "" {
			if _, ok := item.(*ast.NullNode); !ok {
				errs = append(errs, &diagnostic.Error{
					Token:   item.GetToken(),
					Message: fmt.Sprintf("\"on\" elements must be strings, but got %s", item.Type()),
				})
			}
			continue
		}
		if !knownOnEvents[name] {
			errs = append(errs, &diagnostic.Error{
				Token:   item.GetToken(),
				Message: fmt.Sprintf("\"on\" has unknown event %q", name),
			})
		}
	}
	return errs
}

func checkOnMapping(m *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range m.Values {
		eventName := entry.Key.GetToken().Value
		if !knownOnEvents[eventName] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("\"on\" has unknown event %q", eventName),
			})
			continue
		}

		// Event-specific validation
		switch eventName {
		case "schedule":
			errs = append(errs, checkOnSchedule(entry)...)
		case "workflow_dispatch":
			errs = append(errs, checkOnWorkflowDispatch(entry)...)
		default:
			errs = append(errs, checkOnEventFilters(entry)...)
		}
	}
	return errs
}

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
