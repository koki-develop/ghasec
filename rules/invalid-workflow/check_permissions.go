package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
)

func checkPermissions(kv *ast.MappingValueNode) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}

	switch v := kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return checkPermissionsString(v)
	case *ast.MappingNode:
		return checkPermissionsMapping(v)
	case *ast.NullNode:
		// permissions: (with no value) is parsed as null.
		// GitHub Actions treats this as default permissions (NOT the same as {}).
		// However, invalid-workflow only validates structure, not security policy.
		// The default-permissions rule handles enforcing permissions: {}.
		return nil
	default:
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"permissions\" must be a string or mapping, but got %s", kv.Value.Type()),
		}}
	}
}

func checkPermissionsString(node ast.Node) []*diagnostic.Error {
	v := stringValue(node)
	if knownPermissionStrings[v] {
		return nil
	}
	return []*diagnostic.Error{{
		Token:   node.GetToken(),
		Message: fmt.Sprintf("\"permissions\" must be \"read-all\" or \"write-all\", but got %q", v),
	}}
}

func checkPermissionsMapping(m *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range m.Values {
		scope := entry.Key.GetToken().Value
		if !knownPermissionScopes[scope] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("\"permissions\" has unknown scope %q", scope),
			})
			continue
		}

		if isExpression(entry.Value) {
			continue
		}

		level := stringValue(entry.Value)
		if level == "" {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Value.GetToken(),
				Message: fmt.Sprintf("\"permissions\" scope %q must be a string, but got %s", scope, entry.Value.Type()),
			})
			continue
		}

		if scope == "models" {
			if !modelsPermissionLevels[level] {
				errs = append(errs, &diagnostic.Error{
					Token:   entry.Value.GetToken(),
					Message: fmt.Sprintf("\"permissions\" scope %q must be \"read\" or \"none\", but got %q", scope, level),
				})
			}
			continue
		}

		if !knownPermissionLevels[level] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Value.GetToken(),
				Message: fmt.Sprintf("\"permissions\" scope %q must be \"read\", \"write\", or \"none\", but got %q", scope, level),
			})
		}
	}
	return errs
}
