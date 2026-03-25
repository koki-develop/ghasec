package renderer

import (
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

// AgentRenderer outputs diagnostics as Markdown for AI agent consumption.
type AgentRenderer struct {
	rules    map[string]rules.Rule
	hasEntry bool
}

// NewAgent creates an AgentRenderer. The rules map is keyed by rule ID and
// used to look up Why/Fix guidance for each diagnostic.
func NewAgent(ruleList []rules.Rule) *AgentRenderer {
	m := make(map[string]rules.Rule, len(ruleList))
	for _, r := range ruleList {
		m[r.ID()] = r
	}
	return &AgentRenderer{rules: m}
}

// entrySeparator returns a blank line separator between entries.
// The first entry has no separator; subsequent entries are preceded by "\n".
func (r *AgentRenderer) entrySeparator() string {
	if r.hasEntry {
		return "\n"
	}
	r.hasEntry = true
	return ""
}

// printEntry builds and writes a Markdown entry to stdout. It reads the source
// file, extracts the relevant line, and formats the common header + code block.
// The extraFields callback appends rule-specific metadata lines to the builder.
func (r *AgentRenderer) printEntry(path string, tk *token.Token, extraFields func(sb *strings.Builder)) error {
	src, readErr := os.ReadFile(path)
	if readErr != nil {
		return fmt.Errorf("failed to read source file %s: %w", path, readErr)
	}

	content := extractLine(src, tk.Position.Line)

	var sb strings.Builder
	sb.WriteString(r.entrySeparator())
	fmt.Fprintf(&sb, "## %s:%d:%d\n\n", path, tk.Position.Line, tk.Position.Column)
	fmt.Fprintf(&sb, "```yaml\n%s\n```\n\n", content)
	extraFields(&sb)

	_, writeErr := fmt.Fprint(os.Stdout, sb.String())
	return writeErr
}

// PrintParseError renders a YAML parse error as Markdown.
func (r *AgentRenderer) PrintParseError(path string, err error) error {
	yErr, ok := err.(yamlError)
	if !ok {
		return fmt.Errorf("unexpected parse error type for %s: %w", path, err)
	}
	tk := yErr.GetToken()
	if !isValidToken(tk) {
		return fmt.Errorf("parse error without position for %s: %s", path, yErr.GetMessage())
	}
	return r.printEntry(path, tk, func(sb *strings.Builder) {
		fmt.Fprintf(sb, "- **Rule**: parse-error\n")
		fmt.Fprintf(sb, "- **Message**: %s\n", yErr.GetMessage())
	})
}

// PrintDiagnosticError renders a diagnostic error as Markdown.
func (r *AgentRenderer) PrintDiagnosticError(path string, e *diagnostic.Error) error {
	if !isValidToken(e.Token) {
		return fmt.Errorf("diagnostic error without position for %s: %s", path, e.Message)
	}
	return r.printEntry(path, e.Token, func(sb *strings.Builder) {
		fmt.Fprintf(sb, "- **Rule**: %s\n", e.RuleID)
		fmt.Fprintf(sb, "- **Message**: %s\n", e.Message)

		if rule, ok := r.rules[e.RuleID]; ok {
			if ex, ok := rule.(rules.Explainer); ok {
				if w := ex.Why(); w != "" {
					fmt.Fprintf(sb, "- **Why**: %s\n", w)
				}
				if f := ex.Fix(); f != "" {
					fmt.Fprintf(sb, "- **Fix**: %s\n", f)
				}
			}
		}
	})
}

// PrintSummary outputs a summary of the scan results.
// When errors exist, a "---" separator distinguishes the summary from diagnostics above.
func (r *AgentRenderer) PrintSummary(totalFiles, errorCount, errorFileCount, skippedOnline int) error {
	var sb strings.Builder
	if errorCount > 0 {
		sb.WriteString(r.entrySeparator())
		fmt.Fprintf(&sb, "---\n\n")
		fmt.Fprintf(&sb, "%d %s found in %d of %d %s.\n",
			errorCount, pluralize("error", errorCount),
			errorFileCount, totalFiles, pluralize("file", totalFiles))
	} else {
		sb.WriteString(r.entrySeparator())
		fmt.Fprintf(&sb, "No errors found in %d %s.\n", totalFiles, pluralize("file", totalFiles))
	}
	if skippedOnline > 0 {
		sb.WriteString(r.entrySeparator())
		fmt.Fprintf(&sb, "> **Note**: %d online %s skipped. Use `--online` to enable them.\n", skippedOnline, pluralize("rule", skippedOnline))
	}
	_, err := fmt.Fprint(os.Stdout, sb.String())
	return err
}

// PrintHint outputs a hint as a Markdown blockquote.
func (r *AgentRenderer) PrintHint(message string) error {
	var sb strings.Builder
	sb.WriteString(r.entrySeparator())
	fmt.Fprintf(&sb, "> **Hint**: %s\n", message)
	_, err := fmt.Fprint(os.Stdout, sb.String())
	return err
}

// extractLine returns the content of the given 1-based line number from src.
func extractLine(src []byte, line int) string {
	lines := strings.Split(string(src), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}
