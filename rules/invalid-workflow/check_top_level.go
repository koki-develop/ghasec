package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkTopLevelKeys(mapping workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range mapping.Values {
		key := entry.Key.GetToken().Value
		if !knownTopLevelKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("unknown key %q", key),
			})
		}
	}
	return errs
}

func checkDefaults(kv *ast.MappingValueNode) []*diagnostic.Error {
	defaultsMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"defaults\" must be a mapping, but got %s", kv.Value.Type()),
		}}
	}

	var errs []*diagnostic.Error
	for _, entry := range defaultsMapping.Values {
		key := entry.Key.GetToken().Value
		if key != "run" {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("\"defaults\" has unknown key %q", key),
			})
		}
	}

	runKV := workflow.Mapping{MappingNode: defaultsMapping}.FindKey("run")
	if runKV != nil {
		runMapping, ok := runKV.Value.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:   runKV.Value.GetToken(),
				Message: fmt.Sprintf("\"run\" must be a mapping, but got %s", runKV.Value.Type()),
			})
		} else {
			for _, entry := range runMapping.Values {
				key := entry.Key.GetToken().Value
				if !knownDefaultsRunKeys[key] {
					errs = append(errs, &diagnostic.Error{
						Token:   entry.Key.GetToken(),
						Message: fmt.Sprintf("\"run\" has unknown key %q", key),
					})
				}
			}
		}
	}
	return errs
}

func checkConcurrencyMapping(kv *ast.MappingValueNode) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}

	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	}

	concurrencyMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"concurrency\" must be a string or mapping, but got %s", kv.Value.Type()),
		}}
	}

	groupKV := workflow.Mapping{MappingNode: concurrencyMapping}.FindKey("group")
	if groupKV == nil {
		return []*diagnostic.Error{{
			Token:   kv.Key.GetToken(),
			Message: "\"concurrency\" must have a \"group\" key",
		}}
	}

	var errs []*diagnostic.Error
	for _, entry := range concurrencyMapping.Values {
		key := entry.Key.GetToken().Value
		if !knownConcurrencyKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("\"concurrency\" has unknown key %q", key),
			})
		}
	}
	return errs
}
