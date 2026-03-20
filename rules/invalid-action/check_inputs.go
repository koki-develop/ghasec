package invalidaction

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
)

func checkInputs(kv *ast.MappingValueNode) []*diagnostic.Error {
	inputsMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"inputs\" must be a mapping, but got %s", kv.Value.Type()),
		}}
	}

	var errs []*diagnostic.Error
	for _, entry := range inputsMapping.Values {
		entryMapping, ok := entry.Value.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Value.GetToken(),
				Message: fmt.Sprintf("input %q must be a mapping, but got %s", entry.Key.GetToken().Value, entry.Value.Type()),
			})
			continue
		}
		for _, field := range entryMapping.Values {
			key := field.Key.GetToken().Value
			if !knownInputKeys[key] {
				errs = append(errs, &diagnostic.Error{
					Token:   field.Key.GetToken(),
					Message: fmt.Sprintf("input %q has unknown key %q", entry.Key.GetToken().Value, key),
				})
			}
		}
	}
	return errs
}
