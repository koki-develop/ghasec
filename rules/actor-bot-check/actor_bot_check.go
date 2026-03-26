package actorbotcheck

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/expression"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "actor-bot-check"

var targetTriggers = []string{"pull_request", "pull_request_target"}

// Rule detects unreliable github.actor bot comparisons in if: conditions
// of pull_request / pull_request_target workflows.
type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "github.actor in pull request workflows can be manipulated. If someone force-pushes to a bot's branch, the actor changes to the pusher, bypassing bot-identity checks. This makes github.actor-based gates unreliable for security decisions"
}

func (r *Rule) Fix() string {
	return "Use github.event.pull_request.user.login instead of github.actor for bot identity verification. Unlike github.actor, user.login reflects the original PR author and cannot be changed by force-pushing to the branch"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	trigger := matchedTrigger(mapping)
	if trigger == "" {
		return nil
	}

	var errs []*diagnostic.Error

	jobsKV := mapping.FindKey("jobs")
	if jobsKV == nil {
		return nil
	}
	jobsMapping, ok := rules.UnwrapNode(jobsKV.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}

	for _, jobEntry := range jobsMapping.Values {
		jobNode, ok := rules.UnwrapNode(jobEntry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		jm := workflow.Mapping{MappingNode: jobNode}

		// Check job-level if:
		if ifKV := jm.FindKey("if"); ifKV != nil {
			errs = append(errs, checkIfNode(ifKV.Value, trigger)...)
		}

		// Check step-level if:
		stepsKV := jm.FindKey("steps")
		if stepsKV == nil {
			continue
		}
		stepsSeq, ok := rules.UnwrapNode(stepsKV.Value).(*ast.SequenceNode)
		if !ok {
			continue
		}
		for _, stepNode := range stepsSeq.Values {
			stepMapping, ok := rules.UnwrapNode(stepNode).(*ast.MappingNode)
			if !ok {
				continue
			}
			sm := workflow.Mapping{MappingNode: stepMapping}
			if ifKV := sm.FindKey("if"); ifKV != nil {
				errs = append(errs, checkIfNode(ifKV.Value, trigger)...)
			}
		}
	}

	return errs
}

func matchedTrigger(mapping workflow.WorkflowMapping) string {
	onKV := mapping.FindKey("on")
	if onKV == nil {
		return ""
	}

	node := rules.UnwrapNode(onKV.Value)
	switch v := node.(type) {
	case *ast.StringNode:
		for _, t := range targetTriggers {
			if v.Value == t {
				return t
			}
		}
	case *ast.SequenceNode:
		for _, item := range v.Values {
			s := rules.StringValue(item)
			for _, t := range targetTriggers {
				if s == t {
					return t
				}
			}
		}
	case *ast.MappingNode:
		for _, entry := range v.Values {
			key := entry.Key.GetToken().Value
			for _, t := range targetTriggers {
				if key == t {
					return t
				}
			}
		}
	}
	return ""
}

func checkIfNode(node ast.Node, trigger string) []*diagnostic.Error {
	value := rules.StringValue(rules.UnwrapNode(node))
	if value == "" {
		return nil
	}

	var errs []*diagnostic.Error

	// Try extracting explicit ${{ }} expressions
	spans, _ := expression.ExtractExpressions(value)
	if len(spans) > 0 {
		for _, span := range spans {
			parsed, parseErrs := expression.Parse(span.Inner)
			if len(parseErrs) > 0 || parsed == nil {
				continue
			}
			errs = append(errs, findActorBotChecks(node, value, parsed, span.Start+3, trigger)...)
		}
	} else if !strings.Contains(value, "${{") {
		// Bare if: expression (implicit ${{ }})
		parsed, parseErrs := expression.Parse(value)
		if len(parseErrs) > 0 || parsed == nil {
			return nil
		}
		errs = append(errs, findActorBotChecks(node, value, parsed, 0, trigger)...)
	}

	return errs
}

func findActorBotChecks(node ast.Node, value string, exprNode expression.Node, baseOffset int, trigger string) []*diagnostic.Error {
	var errs []*diagnostic.Error
	expression.Walk(exprNode, func(n expression.Node) bool {
		bin, ok := n.(*expression.BinaryNode)
		if !ok {
			return true
		}
		if bin.Op != expression.TokenEQ && bin.Op != expression.TokenNE {
			return true
		}

		actorNode, literalNode := classifyOperands(bin)
		if actorNode == nil || literalNode == nil {
			return true
		}
		if !strings.HasSuffix(literalNode.Value, "[bot]") {
			return true
		}

		// Create a synthetic token pointing to "github.actor"
		spanStart := baseOffset + actorNode.Offset
		spanEnd := spanStart + len("github.actor")
		tok := rules.ExpressionSpanToken(node, value, spanStart, spanEnd)
		errs = append(errs, &diagnostic.Error{
			Token:   tok,
			Message: fmt.Sprintf(`"if" must not use "github.actor" to check for bots in a %q workflow`, trigger),
		})

		return true
	})
	return errs
}

// classifyOperands checks if a binary node has github.actor on one side
// and a string literal on the other. Returns (actorNode, literalNode) or (nil, nil).
func classifyOperands(bin *expression.BinaryNode) (*expression.PropertyAccessNode, *expression.LiteralNode) {
	if actor, lit := matchActorAndLiteral(bin.Left, bin.Right); actor != nil {
		return actor, lit
	}
	return matchActorAndLiteral(bin.Right, bin.Left)
}

func matchActorAndLiteral(a, b expression.Node) (*expression.PropertyAccessNode, *expression.LiteralNode) {
	prop, ok := a.(*expression.PropertyAccessNode)
	if !ok || prop.Property != "actor" {
		return nil, nil
	}
	ident, ok := prop.Object.(*expression.IdentNode)
	if !ok || ident.Name != "github" {
		return nil, nil
	}
	lit, ok := b.(*expression.LiteralNode)
	if !ok || lit.Kind != expression.TokenString {
		return nil, nil
	}
	return prop, lit
}
