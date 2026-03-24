package invalidexpression

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/expression"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-expression"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	r.walkMapping(mapping.Mapping, &errs)
	return errs
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	r.walkMapping(mapping.Mapping, &errs)
	return errs
}

func (r *Rule) walkMapping(m workflow.Mapping, errs *[]*diagnostic.Error) {
	for _, entry := range m.Values {
		key := entry.Key.GetToken().Value
		r.walkNode(entry.Value, errs, key)
	}
}

func (r *Rule) walkNode(node ast.Node, errs *[]*diagnostic.Error, currentKey string) {
	node = rules.UnwrapNode(node)
	switch n := node.(type) {
	case *ast.MappingNode:
		m := workflow.Mapping{MappingNode: n}
		for _, entry := range m.Values {
			key := entry.Key.GetToken().Value
			r.walkNode(entry.Value, errs, key)
		}
	case *ast.SequenceNode:
		for _, item := range n.Values {
			r.walkNode(item, errs, currentKey)
		}
	case *ast.StringNode, *ast.LiteralNode:
		value := rules.StringValue(node)
		if value == "" {
			return
		}

		spans, extractErrs := expression.ExtractExpressions(value)
		for _, e := range extractErrs {
			// For unterminated expressions, create a token covering from ${{ to end of string
			end := len(value)
			if end <= e.Offset {
				end = e.Offset + 3
			}
			if end > len(value) {
				end = len(value)
			}
			spanTok := rules.ExpressionSpanToken(node, value, e.Offset, end)
			*errs = append(*errs, &diagnostic.Error{
				Token:   spanTok,
				Message: fmt.Sprintf("invalid expression syntax: %s", e.Message),
			})
		}
		for _, span := range spans {
			parseErrs := expression.Parse(span.Inner)
			if len(parseErrs) > 0 {
				// Report only the first error per expression span to avoid
				// noisy duplicate diagnostics (e.g., two '"' in ${{ "hello" }}).
				spanTok := rules.ExpressionSpanToken(node, value, span.Start, span.End)
				*errs = append(*errs, &diagnostic.Error{
					Token:   spanTok,
					Message: fmt.Sprintf("invalid expression syntax: %s", parseErrs[0].Message),
				})
			}
		}

		// For if: values without ${{ }}, parse the whole value as an expression
		if currentKey == "if" && len(spans) == 0 && !strings.Contains(value, "${{") {
			parseErrs := expression.Parse(value)
			if len(parseErrs) > 0 {
				e := parseErrs[0]
				trimmedLen := len(strings.TrimRight(value, "\n"))
				start := min(e.Offset, max(trimmedLen-1, 0))
				end := min(start+1, len(value))
				spanTok := rules.ExpressionSpanToken(node, value, start, end)
				*errs = append(*errs, &diagnostic.Error{
					Token:   spanTok,
					Message: fmt.Sprintf("invalid expression syntax: %s", e.Message),
				})
			}
		}
	}
}
