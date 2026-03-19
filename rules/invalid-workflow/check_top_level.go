package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
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
				Message: fmt.Sprintf("unknown top-level key %q", key),
			})
		}
	}
	return errs
}

func checkDefaults(label string, kv *ast.MappingValueNode, contextTokens []*token.Token) []*diagnostic.Error {
	defaultsMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:         kv.Value.GetToken(),
			ContextTokens: contextTokens,
			Message:       fmt.Sprintf("%s \"defaults\" must be a mapping, but got %s", label, kv.Value.Type()),
		}}
	}

	defaultsCtx := extendContext(contextTokens, kv.Key.GetToken())

	var errs []*diagnostic.Error
	for _, entry := range defaultsMapping.Values {
		key := entry.Key.GetToken().Value
		if key != "run" {
			errs = append(errs, &diagnostic.Error{
				Token:         entry.Key.GetToken(),
				ContextTokens: defaultsCtx,
				Message:       fmt.Sprintf("%s \"defaults\" has unknown key %q", label, key),
			})
		}
	}

	runKV := workflow.Mapping{MappingNode: defaultsMapping}.FindKey("run")
	if runKV != nil {
		runMapping, ok := runKV.Value.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:         runKV.Value.GetToken(),
				ContextTokens: defaultsCtx,
				Message:       fmt.Sprintf("%s \"defaults.run\" must be a mapping, but got %s", label, runKV.Value.Type()),
			})
		} else {
			for _, entry := range runMapping.Values {
				key := entry.Key.GetToken().Value
				if !knownDefaultsRunKeys[key] {
					errs = append(errs, &diagnostic.Error{
						Token:         entry.Key.GetToken(),
						ContextTokens: defaultsCtx,
						Message:       fmt.Sprintf("%s \"defaults.run\" has unknown key %q", label, key),
					})
				}
			}
		}
	}
	return errs
}

func checkConcurrencyMapping(label string, kv *ast.MappingValueNode, contextTokens []*token.Token) []*diagnostic.Error {
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
			Token:         kv.Value.GetToken(),
			ContextTokens: contextTokens,
			Message:       fmt.Sprintf("%s \"concurrency\" must be a string or mapping, but got %s", label, kv.Value.Type()),
		}}
	}

	concCtx := extendContext(contextTokens, kv.Key.GetToken())

	groupKV := workflow.Mapping{MappingNode: concurrencyMapping}.FindKey("group")
	if groupKV == nil {
		return []*diagnostic.Error{{
			Token:         kv.Key.GetToken(),
			ContextTokens: concCtx,
			Message:       fmt.Sprintf("%s \"concurrency\" mapping must have a \"group\" key", label),
		}}
	}

	var errs []*diagnostic.Error
	for _, entry := range concurrencyMapping.Values {
		key := entry.Key.GetToken().Value
		if !knownConcurrencyKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:         entry.Key.GetToken(),
				ContextTokens: concCtx,
				Message:       fmt.Sprintf("%s \"concurrency\" has unknown key %q", label, key),
			})
		}
	}
	return errs
}
