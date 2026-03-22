package rules

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
)

// UnwrapNode unwraps AnchorNode wrappers to get the actual value node.
// AliasNode is NOT unwrapped because its Value field contains the alias name,
// not the resolved target.
func UnwrapNode(n ast.Node) ast.Node {
	if n == nil {
		return nil
	}
	for {
		switch v := n.(type) {
		case *ast.AnchorNode:
			n = v.Value
		default:
			return n
		}
	}
}

func IsMapping(n ast.Node) bool {
	n = UnwrapNode(n)
	if _, ok := n.(*ast.AliasNode); ok {
		return true
	}
	_, ok := n.(*ast.MappingNode)
	return ok
}

func IsSequence(n ast.Node) bool {
	n = UnwrapNode(n)
	if _, ok := n.(*ast.AliasNode); ok {
		return true
	}
	_, ok := n.(*ast.SequenceNode)
	return ok
}

func IsString(n ast.Node) bool {
	n = UnwrapNode(n)
	if _, ok := n.(*ast.AliasNode); ok {
		return true
	}
	switch n.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return true
	}
	return false
}

func IsNumber(n ast.Node) bool {
	n = UnwrapNode(n)
	if _, ok := n.(*ast.AliasNode); ok {
		return true
	}
	switch n.(type) {
	case *ast.IntegerNode, *ast.FloatNode:
		return true
	}
	return false
}

func IsBoolean(n ast.Node) bool {
	n = UnwrapNode(n)
	if _, ok := n.(*ast.AliasNode); ok {
		return true
	}
	_, ok := n.(*ast.BoolNode)
	return ok
}

func IsNull(n ast.Node) bool {
	n = UnwrapNode(n)
	_, ok := n.(*ast.NullNode)
	return ok
}

// IsAliasNode returns true if the node (after unwrapping anchors) is an alias.
// Generated validation code uses this to skip type-mismatch diagnostics for
// alias nodes, because the corresponding anchor definition is validated in place.
// This prevents false positives like `"steps" elements must be mappings, but got alias`.
func IsAliasNode(n ast.Node) bool {
	n = UnwrapNode(n)
	_, ok := n.(*ast.AliasNode)
	return ok
}

func IsExpressionNode(n ast.Node) bool {
	v := StringValue(n)
	return v != "" && strings.Contains(v, "${{")
}

func StringValue(n ast.Node) string {
	n = UnwrapNode(n)
	switch v := n.(type) {
	case *ast.StringNode:
		return v.Value
	case *ast.LiteralNode:
		return v.Value.Value
	}
	return ""
}

func NodeTypeName(n ast.Node) string {
	n = UnwrapNode(n)
	switch n.(type) {
	case *ast.AliasNode:
		return "alias"
	case *ast.MappingNode:
		return "mapping"
	case *ast.SequenceNode:
		return "sequence"
	case *ast.StringNode, *ast.LiteralNode:
		return "string"
	case *ast.IntegerNode:
		return "integer"
	case *ast.FloatNode:
		return "float"
	case *ast.BoolNode:
		return "boolean"
	case *ast.NullNode:
		return "null"
	default:
		return "unknown"
	}
}

// JoinOr formats alternatives with proper English: "a", "a or b", "a, b, or c".
func JoinOr(items []string) string {
	switch len(items) {
	case 0:
		return "(none)"
	case 1:
		return items[0]
	case 2:
		return items[0] + " or " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", or " + items[len(items)-1]
	}
}

// JoinPlural formats allowed types in plural form: "strings", "mappings", etc.
func JoinPlural(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	plural := make([]string, len(items))
	for i, a := range items {
		plural[i] = a + "s"
	}
	return JoinOr(plural)
}
