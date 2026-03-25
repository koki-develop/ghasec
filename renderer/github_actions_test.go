package renderer

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = old
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return string(out)
}

// mockYAMLError implements the yamlError interface for testing.
type mockYAMLError struct {
	token   *token.Token
	message string
}

func (e *mockYAMLError) Error() string          { return e.message }
func (e *mockYAMLError) GetToken() *token.Token { return e.token }
func (e *mockYAMLError) GetMessage() string     { return e.message }

func TestGitHubActionsRenderer_PrintDiagnosticError(t *testing.T) {
	rdr := NewGitHubActions()
	tk := &token.Token{
		Value:    "actions/checkout@v6",
		Position: &token.Position{Line: 8, Column: 15},
	}
	e := &diagnostic.Error{
		Token:   tk,
		RuleID:  "unpinned-action",
		Message: `"actions/checkout@v6" must be pinned to a full length commit SHA`,
	}
	output := captureStdout(t, func() {
		err := rdr.PrintDiagnosticError("workflow.yml", e)
		require.NoError(t, err)
	})
	assert.Equal(t,
		"::error title=unpinned-action,file=workflow.yml,line=8::workflow.yml:8:15: \"actions/checkout@v6\" must be pinned to a full length commit SHA\n",
		output)
}

func TestGitHubActionsRenderer_PrintParseError(t *testing.T) {
	rdr := NewGitHubActions()
	tk := &token.Token{
		Value:    "bad",
		Position: &token.Position{Line: 1, Column: 1},
	}
	parseErr := &mockYAMLError{token: tk, message: "found invalid token"}
	output := captureStdout(t, func() {
		err := rdr.PrintParseError("broken.yml", parseErr)
		require.NoError(t, err)
	})
	assert.Equal(t,
		"::error title=parse-error,file=broken.yml,line=1::broken.yml:1:1: found invalid token\n",
		output)
}

func TestGitHubActionsRenderer_PrintDiagnosticError_NilToken(t *testing.T) {
	rdr := NewGitHubActions()
	e := &diagnostic.Error{
		Token:   nil,
		RuleID:  "some-rule",
		Message: "some message",
	}
	err := rdr.PrintDiagnosticError("file.yml", e)
	assert.Error(t, err)
}

func TestGitHubActionsRenderer_PrintDiagnosticError_NilPosition(t *testing.T) {
	rdr := NewGitHubActions()
	e := &diagnostic.Error{
		Token:   &token.Token{Position: nil},
		RuleID:  "some-rule",
		Message: "some message",
	}
	err := rdr.PrintDiagnosticError("file.yml", e)
	assert.Error(t, err)
}

func TestGitHubActionsRenderer_PrintParseError_NonYAMLError(t *testing.T) {
	rdr := NewGitHubActions()
	err := rdr.PrintParseError("file.yml", fmt.Errorf("not a yaml error"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected parse error type")
}

func TestGitHubActionsRenderer_PrintParseError_NilToken(t *testing.T) {
	rdr := NewGitHubActions()
	parseErr := &mockYAMLError{token: nil, message: "bad"}
	err := rdr.PrintParseError("file.yml", parseErr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse error without position")
}

func TestGitHubActionsRenderer_PrintParseError_NilPosition(t *testing.T) {
	rdr := NewGitHubActions()
	parseErr := &mockYAMLError{token: &token.Token{Position: nil}, message: "bad"}
	err := rdr.PrintParseError("file.yml", parseErr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse error without position")
}

func TestGitHubActionsRenderer_PrintDiagnosticError_EscapedMessage(t *testing.T) {
	rdr := NewGitHubActions()
	tk := &token.Token{
		Value:    "val",
		Position: &token.Position{Line: 1, Column: 1},
	}
	e := &diagnostic.Error{
		Token:   tk,
		RuleID:  "rule-id",
		Message: "msg with 100% and\nnewline",
	}
	output := captureStdout(t, func() {
		err := rdr.PrintDiagnosticError("file.yml", e)
		require.NoError(t, err)
	})
	assert.Equal(t,
		"::error title=rule-id,file=file.yml,line=1::file.yml:1:1: msg with 100%25 and%0Anewline\n",
		output)
}

func TestGitHubActionsRenderer_PrintDiagnosticError_EscapedPath(t *testing.T) {
	rdr := NewGitHubActions()
	tk := &token.Token{
		Value:    "val",
		Position: &token.Position{Line: 1, Column: 1},
	}
	e := &diagnostic.Error{
		Token:   tk,
		RuleID:  "rule-id",
		Message: "msg",
	}
	output := captureStdout(t, func() {
		err := rdr.PrintDiagnosticError("path:with,special", e)
		require.NoError(t, err)
	})
	assert.Equal(t,
		"::error title=rule-id,file=path%3Awith%2Cspecial,line=1::path:with,special:1:1: msg\n",
		output)
}

func TestEscapeData(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no special chars", "hello world", "hello world"},
		{"percent", "100%", "100%25"},
		{"newline", "line1\nline2", "line1%0Aline2"},
		{"carriage return", "line1\rline2", "line1%0Dline2"},
		{"mixed", "100%\nfoo\rbar", "100%25%0Afoo%0Dbar"},
		{"percent before newline encoding", "%0A literal", "%250A literal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, escapeData(tt.input))
		})
	}
}

func TestEscapeProperty(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no special chars", "hello", "hello"},
		{"colon", "file:name", "file%3Aname"},
		{"comma", "a,b", "a%2Cb"},
		{"all special", "a%b:c,d\ne\rf", "a%25b%3Ac%2Cd%0Ae%0Df"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, escapeProperty(tt.input))
		})
	}
}
