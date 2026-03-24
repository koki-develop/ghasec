package renderer

import (
	"fmt"
	"os"
	"strings"

	"github.com/koki-develop/ghasec/diagnostic"
)

// GitHubActionsRenderer outputs diagnostics as GitHub Actions workflow commands.
// Format: ::error title=<title>,file=<file>,line=<line>::<message>
type GitHubActionsRenderer struct{}

// NewGitHubActions creates a GitHubActionsRenderer.
func NewGitHubActions() *GitHubActionsRenderer {
	return &GitHubActionsRenderer{}
}

// PrintParseError renders a YAML parse error as a GitHub Actions ::error command.
func (r *GitHubActionsRenderer) PrintParseError(path string, err error) error {
	yErr, ok := err.(yamlError)
	if !ok {
		return fmt.Errorf("unexpected parse error type for %s: %w", path, err)
	}
	tk := yErr.GetToken()
	if !isValidToken(tk) {
		return fmt.Errorf("parse error without position for %s: %s", path, yErr.GetMessage())
	}
	_, writeErr := fmt.Fprintf(os.Stdout, "::error title=%s,file=%s,line=%d::%s\n",
		escapeProperty("parse-error"),
		escapeProperty(path),
		tk.Position.Line,
		escapeData(yErr.GetMessage()))
	return writeErr
}

// PrintDiagnosticError renders a diagnostic error as a GitHub Actions ::error command.
func (r *GitHubActionsRenderer) PrintDiagnosticError(path string, e *diagnostic.Error) error {
	if !isValidToken(e.Token) {
		return fmt.Errorf("diagnostic error without position for %s: %s", path, e.Message)
	}
	_, err := fmt.Fprintf(os.Stdout, "::error title=%s,file=%s,line=%d::%s\n",
		escapeProperty(e.RuleID),
		escapeProperty(path),
		e.Token.Position.Line,
		escapeData(e.Message))
	return err
}

// escapeData escapes special characters in workflow command message data.
// Order matters: % must be escaped first to avoid double-escaping.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeProperty escapes special characters in workflow command property values.
// Extends escapeData with additional delimiters used in the property syntax.
func escapeProperty(s string) string {
	s = escapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}
