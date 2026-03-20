package invalidaction

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkOutputs(kv *ast.MappingValueNode, using string) []*diagnostic.Error {
	outputsMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"outputs\" must be a mapping, but got %s", kv.Value.Type()),
		}}
	}

	allowedKeys := knownOutputKeys
	if using == "composite" {
		allowedKeys = knownCompositeOutputKeys
	}

	var errs []*diagnostic.Error
	for _, entry := range outputsMapping.Values {
		entryMapping, ok := entry.Value.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Value.GetToken(),
				Message: fmt.Sprintf("output %q must be a mapping, but got %s", entry.Key.GetToken().Value, entry.Value.Type()),
			})
			continue
		}

		m := workflow.Mapping{MappingNode: entryMapping}

		for _, field := range entryMapping.Values {
			key := field.Key.GetToken().Value
			if !allowedKeys[key] {
				errs = append(errs, &diagnostic.Error{
					Token:   field.Key.GetToken(),
					Message: fmt.Sprintf("output %q has unknown key %q", entry.Key.GetToken().Value, key),
				})
			}
		}

		if using == "composite" && m.FindKey("value") == nil {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: "\"value\" is required",
			})
		}
	}
	return errs
}
