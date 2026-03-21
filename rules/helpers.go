package rules

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
)

func IsMapping(n ast.Node) bool  { _, ok := n.(*ast.MappingNode); return ok }
func IsSequence(n ast.Node) bool { _, ok := n.(*ast.SequenceNode); return ok }
func IsString(n ast.Node) bool {
	switch n.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return true
	}
	return false
}
func IsNumber(n ast.Node) bool {
	switch n.(type) {
	case *ast.IntegerNode, *ast.FloatNode:
		return true
	}
	return false
}
func IsBoolean(n ast.Node) bool { _, ok := n.(*ast.BoolNode); return ok }
func IsNull(n ast.Node) bool    { _, ok := n.(*ast.NullNode); return ok }
func IsExpressionNode(n ast.Node) bool {
	v := StringValue(n)
	return v != "" && strings.Contains(v, "${{")
}
func StringValue(n ast.Node) string {
	switch v := n.(type) {
	case *ast.StringNode:
		return v.Value
	case *ast.LiteralNode:
		return v.Value.Value
	}
	return ""
}
func NodeTypeName(n ast.Node) string {
	switch n.(type) {
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
