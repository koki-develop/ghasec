package deprecatedcommands

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
	"mvdan.cc/sh/v3/syntax"
)

const id = "deprecated-commands"

// deprecatedPrefixes maps each deprecated workflow command prefix to its
// canonical name used in diagnostic messages.
var deprecatedPrefixes = []struct {
	prefix string
	name   string
}{
	{"::set-env ", "::set-env"},
	{"::add-path::", "::add-path"},
	{"::set-output ", "::set-output"},
	{"::save-state ", "::save-state"},
}

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Deprecated workflow commands (set-env, add-path, set-output, save-state) are superseded by environment files. set-env and add-path have known security vulnerabilities that allow environment variable injection"
}

func (r *Rule) Fix() string {
	return "Replace deprecated commands with environment file equivalents: use $GITHUB_ENV instead of ::set-env, $GITHUB_PATH instead of ::add-path, $GITHUB_OUTPUT instead of ::set-output, and $GITHUB_STATE instead of ::save-state. Remove any ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable settings"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	// Check env at workflow level.
	errs = append(errs, checkEnvMapping(mapping.Mapping)...)

	// Check env at job level and step-level env via manual job iteration.
	jobsKV := mapping.FindKey("jobs")
	if jobsKV != nil {
		jobsMapping, ok := rules.UnwrapNode(jobsKV.Value).(*ast.MappingNode)
		if ok {
			for _, jobEntry := range jobsMapping.Values {
				jobMapping, ok := rules.UnwrapNode(jobEntry.Value).(*ast.MappingNode)
				if !ok {
					continue
				}
				errs = append(errs, checkEnvMapping(workflow.Mapping{MappingNode: jobMapping})...)
			}
		}
	}

	// Check deprecated commands in run steps and step-level env.
	mapping.EachStep(func(step workflow.StepMapping) {
		errs = append(errs, checkStep(step)...)
	})

	return errs
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		errs = append(errs, checkStep(step)...)
	})
	return errs
}

func checkStep(step workflow.StepMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	errs = append(errs, checkEnvMapping(step.Mapping)...)
	errs = append(errs, checkRun(step)...)
	return errs
}

func checkRun(step workflow.StepMapping) []*diagnostic.Error {
	runKV := step.FindKey("run")
	if runKV == nil {
		return nil
	}

	value := rules.StringValue(runKV.Value)
	if value == "" {
		return nil
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(value), "")
	if err != nil {
		// Invalid shell — not this rule's concern.
		return nil
	}

	var errs []*diagnostic.Error
	syntax.Walk(f, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		cmdName := call.Args[0].Lit()
		if cmdName != "echo" && cmdName != "printf" && cmdName != "print" {
			return true
		}

		for _, arg := range call.Args[1:] {
			literal := wordLiteral(arg)
			if literal == "" {
				continue
			}
			for _, dp := range deprecatedPrefixes {
				if strings.HasPrefix(literal, dp.prefix) {
					tok := shellSpanToken(runKV.Value, value, arg)
					errs = append(errs, &diagnostic.Error{
						Token:   tok,
						Message: fmt.Sprintf("deprecated workflow command %q must not be used", dp.name),
					})
					break
				}
			}
		}
		return true
	})

	return errs
}

// wordLiteral extracts the literal text from a shell word, concatenating
// all literal parts. Returns "" if the word contains non-literal parts
// that prevent static analysis (parameter expansions, command substitutions, etc.).
func wordLiteral(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return ""
				}
				sb.WriteString(lit.Value)
			}
		default:
			return ""
		}
	}
	return sb.String()
}

// shellWordQuoteOffset returns the number of characters to skip past shell-level
// quotes to reach the actual content. For quoted words ('...' or "..."), the
// shell parser Pos() points to the opening quote, so we need +1 to reach the content.
func shellWordQuoteOffset(word *syntax.Word) int {
	if len(word.Parts) == 1 {
		switch word.Parts[0].(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return 1
		}
	}
	return 0
}

// shellSpanToken creates a synthetic token pointing to a shell word's position
// within the YAML run: value. It maps shell parser positions (1-based line/col
// within the parsed script) back to YAML source positions.
func shellSpanToken(node ast.Node, value string, word *syntax.Word) *token.Token {
	base := node.GetToken()
	wordValue := wordLiteral(word)

	shellLine := int(word.Pos().Line()) // 1-based
	shellCol := int(word.Pos().Col())   // 1-based

	// Adjust for shell-level quotes (point to content, not the quote character).
	shellQuoteOffset := shellWordQuoteOffset(word)
	shellCol += shellQuoteOffset

	// For literal block scalars (| or >), compute the correct position.
	if lit, ok := rules.UnwrapNode(node).(*ast.LiteralNode); ok {
		return literalShellSpanToken(lit, value, shellLine, shellCol, wordValue)
	}

	// For inline/quoted strings, the script is on the same line as the base token.
	// yamlQuoteOffset accounts for YAML-level quoting (run: "..." or run: '...').
	yamlQuoteOffset := 0
	if base.Origin != "" {
		trimmed := strings.TrimLeft(base.Origin, " \t\n\r")
		if len(trimmed) > 0 && (trimmed[0] == '\'' || trimmed[0] == '"') {
			yamlQuoteOffset = 1
		}
	}

	return &token.Token{
		Type:  base.Type,
		Value: wordValue,
		Prev:  base.Prev,
		Position: &token.Position{
			Line:   base.Position.Line + shellLine - 1,
			Column: base.Position.Column + yamlQuoteOffset + shellCol - 1,
			Offset: base.Position.Offset + yamlQuoteOffset + shellCol - 1,
		},
	}
}

// literalShellSpanToken creates a token for a shell word within a block scalar.
func literalShellSpanToken(lit *ast.LiteralNode, value string, shellLine, shellCol int, wordValue string) *token.Token {
	base := lit.Start

	// Derive content indentation from Origin vs Value comparison.
	indent := 0
	valTok := lit.Value.GetToken()
	if valTok.Origin != "" && value != "" {
		originFirst := strings.SplitN(valTok.Origin, "\n", 2)[0]
		valueFirst := strings.SplitN(value, "\n", 2)[0]
		if d := len(originFirst) - len(valueFirst); d > 0 {
			indent = d
		}
	}

	// Shell line L, column C → YAML line = base line + L, column = indent + C
	line := base.Position.Line + shellLine
	col := indent + shellCol

	return &token.Token{
		Type:  base.Type,
		Value: wordValue,
		Prev:  base.Prev,
		Position: &token.Position{
			Line:   line,
			Column: col,
			Offset: base.Position.Offset + shellCol - 1,
		},
	}
}

// checkEnvMapping checks a mapping for an "env" key containing
// ACTIONS_ALLOW_UNSECURE_COMMANDS set to true.
func checkEnvMapping(m workflow.Mapping) []*diagnostic.Error {
	envKV := m.FindKey("env")
	if envKV == nil {
		return nil
	}

	envMapping, ok := rules.UnwrapNode(envKV.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}

	for _, entry := range envMapping.Values {
		key := entry.Key.GetToken().Value
		if key != "ACTIONS_ALLOW_UNSECURE_COMMANDS" {
			continue
		}

		if isTrueValue(entry.Value) {
			return []*diagnostic.Error{{
				Token:   entry.Key.GetToken(),
				Message: `"ACTIONS_ALLOW_UNSECURE_COMMANDS" must not be enabled`,
			}}
		}
	}

	return nil
}

// isTrueValue checks if a YAML value node represents the boolean true,
// using C# Boolean.TryParse semantics: only the case-insensitive string
// "true" (after trimming whitespace) is considered true.
func isTrueValue(node ast.Node) bool {
	switch v := rules.UnwrapNode(node).(type) {
	case *ast.BoolNode:
		return v.Value
	case *ast.StringNode:
		return strings.TrimSpace(strings.ToLower(v.Value)) == "true"
	case *ast.LiteralNode:
		return strings.TrimSpace(strings.ToLower(v.Value.Value)) == "true"
	}
	return false
}
