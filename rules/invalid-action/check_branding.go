package invalidaction

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkBranding(kv *ast.MappingValueNode) []*diagnostic.Error {
	brandingMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"branding\" must be a mapping, but got %s", kv.Value.Type()),
		}}
	}

	m := workflow.Mapping{MappingNode: brandingMapping}
	var errs []*diagnostic.Error

	for _, entry := range brandingMapping.Values {
		key := entry.Key.GetToken().Value
		if !knownBrandingKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("\"branding\" has unknown key %q", key),
			})
		}
	}

	if colorKV := m.FindKey("color"); colorKV != nil {
		var colorValue string
		switch v := colorKV.Value.(type) {
		case *ast.StringNode:
			colorValue = v.Value
		case *ast.LiteralNode:
			colorValue = v.Value.Value
		default:
			errs = append(errs, &diagnostic.Error{
				Token:   colorKV.Value.GetToken(),
				Message: fmt.Sprintf("\"color\" must be a string, but got %s", colorKV.Value.Type()),
			})
		}
		if colorValue != "" && !knownBrandingColors[colorValue] {
			errs = append(errs, &diagnostic.Error{
				Token:   colorKV.Value.GetToken(),
				Message: fmt.Sprintf("\"branding\" has unknown color %q", colorValue),
			})
		}
	}

	if iconKV := m.FindKey("icon"); iconKV != nil {
		var iconValue string
		switch v := iconKV.Value.(type) {
		case *ast.StringNode:
			iconValue = v.Value
		case *ast.LiteralNode:
			iconValue = v.Value.Value
		default:
			errs = append(errs, &diagnostic.Error{
				Token:   iconKV.Value.GetToken(),
				Message: fmt.Sprintf("\"icon\" must be a string, but got %s", iconKV.Value.Type()),
			})
		}
		if iconValue != "" && !knownBrandingIcons[iconValue] {
			errs = append(errs, &diagnostic.Error{
				Token:   iconKV.Value.GetToken(),
				Message: fmt.Sprintf("\"branding\" has unknown icon %q", iconValue),
			})
		}
	}

	return errs
}
