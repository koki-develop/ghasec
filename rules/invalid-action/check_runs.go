package invalidaction

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkRuns(kv *ast.MappingValueNode) (string, []*diagnostic.Error) {
	runsMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return "", []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"runs\" must be a mapping, but got %s", kv.Value.Type()),
		}}
	}

	m := workflow.Mapping{MappingNode: runsMapping}

	usingKV := m.FindKey("using")
	if usingKV == nil {
		return "", []*diagnostic.Error{{
			Token:   kv.Key.GetToken(),
			Message: "\"using\" is required",
		}}
	}

	usingValue := ""
	switch v := usingKV.Value.(type) {
	case *ast.StringNode:
		usingValue = v.Value
	case *ast.LiteralNode:
		usingValue = v.Value.Value
	default:
		return "", []*diagnostic.Error{{
			Token:   usingKV.Value.GetToken(),
			Message: fmt.Sprintf("\"using\" must be a string, but got %s", usingKV.Value.Type()),
		}}
	}

	if !knownUsingValues[usingValue] {
		return "", []*diagnostic.Error{{
			Token:   usingKV.Value.GetToken(),
			Message: fmt.Sprintf("\"runs\" has unknown \"using\" value %q", usingValue),
		}}
	}

	var errs []*diagnostic.Error

	switch {
	case jsUsingValues[usingValue]:
		if m.FindKey("main") == nil {
			errs = append(errs, &diagnostic.Error{
				Token:   kv.Key.GetToken(),
				Message: "\"main\" is required",
			})
		}
		for _, entry := range runsMapping.Values {
			key := entry.Key.GetToken().Value
			if !knownJSRunsKeys[key] {
				errs = append(errs, &diagnostic.Error{
					Token:   entry.Key.GetToken(),
					Message: fmt.Sprintf("\"runs\" has unknown key %q", key),
				})
			}
		}

	case usingValue == "composite":
		stepsKV := m.FindKey("steps")
		if stepsKV == nil {
			errs = append(errs, &diagnostic.Error{
				Token:   kv.Key.GetToken(),
				Message: "\"steps\" is required",
			})
		} else {
			stepsSeq, ok := stepsKV.Value.(*ast.SequenceNode)
			if !ok {
				errs = append(errs, &diagnostic.Error{
					Token:   stepsKV.Value.GetToken(),
					Message: fmt.Sprintf("\"steps\" must be a sequence, but got %s", stepsKV.Value.Type()),
				})
			} else {
				errs = append(errs, checkStepEntries(stepsSeq)...)
			}
		}
		for _, entry := range runsMapping.Values {
			key := entry.Key.GetToken().Value
			if !knownCompositeRunsKeys[key] {
				errs = append(errs, &diagnostic.Error{
					Token:   entry.Key.GetToken(),
					Message: fmt.Sprintf("\"runs\" has unknown key %q", key),
				})
			}
		}

	case usingValue == "docker":
		if m.FindKey("image") == nil {
			errs = append(errs, &diagnostic.Error{
				Token:   kv.Key.GetToken(),
				Message: "\"image\" is required",
			})
		}
		for _, entry := range runsMapping.Values {
			key := entry.Key.GetToken().Value
			if !knownDockerRunsKeys[key] {
				errs = append(errs, &diagnostic.Error{
					Token:   entry.Key.GetToken(),
					Message: fmt.Sprintf("\"runs\" has unknown key %q", key),
				})
			}
		}
	}

	return usingValue, errs
}
