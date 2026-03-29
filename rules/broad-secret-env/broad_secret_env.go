package broadsecretenv

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/expression"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "broad-secret-env"

// Rule detects secrets and github.token in workflow-level and job-level
// environment variables, where they are exposed to all steps in scope.
type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Setting secrets or github.token in workflow-level or job-level environment variables exposes them to all steps in the scope, including third-party actions that do not need access. This violates the principle of least privilege and increases the risk of secret exfiltration"
}

func (r *Rule) Fix() string {
	return "Move the secret to a step-level environment variable so that only the step that needs it has access"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	// Check workflow-level env
	errs = append(errs, checkEnv(mapping.FindKey("env"), "workflow")...)

	// Check job-level env
	errs = append(errs, rules.CollectJobErrors(mapping.EachJob, func(_ *token.Token, job workflow.JobMapping) []*diagnostic.Error {
		return checkEnv(job.FindKey("env"), "job")
	})...)

	return errs
}

func checkEnv(envKV *ast.MappingValueNode, level string) []*diagnostic.Error {
	if envKV == nil {
		return nil
	}
	envMapping, ok := rules.UnwrapNode(envKV.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	for _, entry := range envMapping.Values {
		errs = append(errs, checkValue(entry.Value, level)...)
	}
	return errs
}

func checkValue(node ast.Node, level string) []*diagnostic.Error {
	value := rules.StringValue(node)
	if value == "" {
		return nil
	}

	spans, _ := expression.ExtractExpressions(value)
	if len(spans) == 0 {
		return nil
	}

	var errs []*diagnostic.Error
	for _, span := range spans {
		parsed, parseErrs := expression.Parse(span.Inner)
		if len(parseErrs) > 0 || parsed == nil {
			continue
		}

		// innerBase is the byte offset of Inner[0] within value.
		innerBase := span.Start + 3 // 3 = len("${{")

		expression.Walk(parsed, func(n expression.Node) bool {
			match := matchSecret(n, span.Inner)
			if match.subject == "" {
				return true
			}
			subStart := innerBase + match.start
			subEnd := innerBase + match.end
			tok := rules.ExpressionSpanToken(node, value, subStart, subEnd)
			errs = append(errs, &diagnostic.Error{
				Token:   tok,
				Message: match.subject + " must not be set in " + level + "-level environment variables; set them in step-level environment variables instead",
			})
			return true
		})
	}
	return errs
}

type secretMatch struct {
	subject    string // "secrets" or "github.token", or "" if no match
	start, end int    // byte offsets within the expression Inner string
}

// matchSecret checks if the node accesses a secret value and returns
// the diagnostic subject and the byte range within the Inner string.
func matchSecret(n expression.Node, inner string) secretMatch {
	switch v := n.(type) {
	case *expression.PropertyAccessNode:
		ident, ok := v.Object.(*expression.IdentNode)
		if !ok {
			return secretMatch{}
		}
		if ident.Name == "secrets" {
			start := ident.Offset
			end := start + len(ident.Name) + 1 + len(v.Property) // ident + "." + property
			return secretMatch{subject: "secrets", start: start, end: end}
		}
		if ident.Name == "github" && v.Property == "token" {
			start := ident.Offset
			end := start + len(ident.Name) + 1 + len(v.Property)
			return secretMatch{subject: "github.token", start: start, end: end}
		}
	case *expression.IndexAccessNode:
		ident, ok := v.Object.(*expression.IdentNode)
		if !ok {
			return secretMatch{}
		}
		start := ident.Offset
		end := findClosingBracket(inner, v.Offset)
		if ident.Name == "secrets" {
			return secretMatch{subject: "secrets", start: start, end: end}
		}
		if ident.Name == "github" {
			lit, ok := v.Index.(*expression.LiteralNode)
			if ok && lit.Kind == expression.TokenString && lit.Value == "token" {
				return secretMatch{subject: "github.token", start: start, end: end}
			}
		}
	}
	return secretMatch{}
}

// findClosingBracket finds the position after ']' starting from the '[' at pos.
func findClosingBracket(inner string, pos int) int {
	for i := pos + 1; i < len(inner); i++ {
		if inner[i] == ']' {
			return i + 1
		}
	}
	return len(inner)
}
