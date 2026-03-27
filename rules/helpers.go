package rules

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/expression"
	"github.com/koki-develop/ghasec/workflow"
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

// ExpressionSpanToken creates a synthetic token that points to a ${{ }} span
// within a string value, for precise error positioning. It adjusts the line,
// column, and value to cover only the expression span (e.g., "${{ github.actor }}")
// rather than the entire string.
//
// For block scalars (| and >), the function correctly computes the line and
// column by accounting for newlines within the value and the content indentation.
//
// spanStart is the byte offset of "${{" within the string value.
// spanEnd is the byte offset past "}}" within the string value.
func ExpressionSpanToken(node ast.Node, value string, spanStart, spanEnd int) *token.Token {
	base := node.GetToken()

	// For literal block scalars, compute the correct line and column by
	// counting newlines in the value prefix and using the content indentation.
	if lit, ok := UnwrapNode(node).(*ast.LiteralNode); ok {
		return literalSpanToken(lit, value, spanStart, spanEnd)
	}

	// For inline/quoted strings, the expression is on the same line as the
	// base token. Adjust the column by the span offset within the value.
	quoteOffset := 0
	if base.Origin != "" {
		trimmed := strings.TrimLeft(base.Origin, " \t\n\r")
		if len(trimmed) > 0 && (trimmed[0] == '\'' || trimmed[0] == '"') {
			quoteOffset = 1
		}
	}
	return &token.Token{
		Type:  base.Type,
		Value: value[spanStart:spanEnd],
		Prev:  base.Prev,
		Position: &token.Position{
			Line:   base.Position.Line,
			Column: base.Position.Column + quoteOffset + spanStart,
			Offset: base.Position.Offset + quoteOffset + spanStart,
		},
	}
}

// literalSpanToken creates a synthetic token for a span within a block scalar
// (| or >). It derives the correct source line and column by:
// 1. Counting newlines in the value before spanStart to determine line offset
// 2. Computing the column as the distance from the last newline + content indentation
// 3. Using the block indicator line + 1 + lineOffset as the actual source line
func literalSpanToken(lit *ast.LiteralNode, value string, spanStart, spanEnd int) *token.Token {
	base := lit.Start

	// Derive content indentation by comparing Origin (raw, with indent) to
	// Value (parsed, indent stripped). The difference in the first line's
	// length gives the indentation width.
	indent := 0
	valTok := lit.Value.GetToken()
	if valTok.Origin != "" && value != "" {
		originFirst := strings.SplitN(valTok.Origin, "\n", 2)[0]
		valueFirst := strings.SplitN(value, "\n", 2)[0]
		if d := len(originFirst) - len(valueFirst); d > 0 {
			indent = d
		}
	}

	// Count newlines before spanStart to find the line offset within the value.
	prefix := value[:spanStart]
	lineOffset := strings.Count(prefix, "\n")

	// Compute column: distance from the last newline in prefix (or from start
	// if no newlines) gives the column within the stripped value line. Add the
	// content indentation to get the actual source column (1-indexed).
	// When there are no newlines, LastIndex returns -1, so (spanStart - (-1) - 1) == spanStart.
	lastNL := strings.LastIndex(prefix, "\n")
	col := indent + (spanStart - lastNL - 1) + 1

	// The actual source line: | indicator line + 1 (first content line) + lineOffset
	line := base.Position.Line + 1 + lineOffset

	return &token.Token{
		Type:  base.Type,
		Value: value[spanStart:spanEnd],
		Prev:  base.Prev,
		Position: &token.Position{
			Line:   line,
			Column: col,
			Offset: base.Position.Offset + spanStart, // approximate
		},
	}
}

// ExpressionSpanTokens returns a synthetic token for each ${{ }} span in a
// string node's value. If the value contains no expressions, returns nil.
func ExpressionSpanTokens(node ast.Node) []*token.Token {
	value := StringValue(node)
	if value == "" {
		return nil
	}
	spans, errs := expression.ExtractExpressions(value)
	if len(spans) == 0 && len(errs) == 0 {
		return nil
	}
	var tokens []*token.Token
	for _, span := range spans {
		tokens = append(tokens, ExpressionSpanToken(node, value, span.Start, span.End))
	}
	// For unterminated expressions, create a token covering from "${{" to end of string
	for _, e := range errs {
		end := len(value)
		if end <= e.Offset {
			end = e.Offset + 3
		}
		if end > len(value) {
			end = len(value)
		}
		tokens = append(tokens, ExpressionSpanToken(node, value, e.Offset, end))
	}
	return tokens
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

// CollectStepErrors collects errors from a step check that returns a slice.
func CollectStepErrors(eachStep func(func(workflow.StepMapping)), check func(workflow.StepMapping) []*diagnostic.Error) []*diagnostic.Error {
	var errs []*diagnostic.Error
	eachStep(func(step workflow.StepMapping) {
		errs = append(errs, check(step)...)
	})
	return errs
}

// CollectStepError collects errors from a step check that returns a single error.
func CollectStepError(eachStep func(func(workflow.StepMapping)), check func(workflow.StepMapping) *diagnostic.Error) []*diagnostic.Error {
	var errs []*diagnostic.Error
	eachStep(func(step workflow.StepMapping) {
		if err := check(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

// CollectJobErrors collects errors from a job check that returns a slice.
func CollectJobErrors(eachJob func(func(*token.Token, workflow.JobMapping)), check func(*token.Token, workflow.JobMapping) []*diagnostic.Error) []*diagnostic.Error {
	var errs []*diagnostic.Error
	eachJob(func(jobKeyToken *token.Token, job workflow.JobMapping) {
		errs = append(errs, check(jobKeyToken, job)...)
	})
	return errs
}

// CollectJobError collects errors from a job check that returns a single error.
func CollectJobError(eachJob func(func(*token.Token, workflow.JobMapping)), check func(*token.Token, workflow.JobMapping) *diagnostic.Error) []*diagnostic.Error {
	var errs []*diagnostic.Error
	eachJob(func(jobKeyToken *token.Token, job workflow.JobMapping) {
		if err := check(jobKeyToken, job); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}
