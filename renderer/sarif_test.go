package renderer

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRule is a minimal rules.Rule implementation for testing.
type stubRule struct {
	id string
}

func (r *stubRule) ID() string     { return r.id }
func (r *stubRule) Required() bool { return false }
func (r *stubRule) Online() bool   { return false }

// stubExplainerRule implements both rules.Rule and rules.Explainer.
type stubExplainerRule struct {
	stubRule
	why string
}

func (r *stubExplainerRule) Why() string { return r.why }
func (r *stubExplainerRule) Fix() string { return "" }

func TestSARIFRenderer_DiagnosticError(t *testing.T) {
	ruleList := []rules.Rule{&stubExplainerRule{stubRule: stubRule{id: "unpinned-action"}, why: "Tags are mutable"}}
	rdr := NewSARIF(ruleList, "1.0.0")

	tk := &token.Token{
		Value:    "actions/checkout@v6",
		Position: &token.Position{Line: 8, Column: 15},
	}
	e := &diagnostic.Error{
		Token:   tk,
		RuleID:  "unpinned-action",
		Message: `"actions/checkout@v6" must be pinned to a full length commit SHA`,
	}

	require.NoError(t, rdr.PrintDiagnosticError("workflow.yml", e))

	output := captureStdout(t, func() {
		require.NoError(t, rdr.PrintSummary(1, 1, 1, 0))
	})

	var log sarifLog
	require.NoError(t, json.Unmarshal([]byte(output), &log))

	assert.Equal(t, "2.1.0", log.Version)
	assert.Equal(t, sarifSchemaURI, log.Schema)
	require.Len(t, log.Runs, 1)

	run := log.Runs[0]
	assert.Equal(t, "ghasec", run.Tool.Driver.Name)
	assert.Equal(t, "1.0.0", run.Tool.Driver.Version)

	// rules[0] is parse-error, rules[1] is unused-ignore, rules[2] is unpinned-action
	require.Len(t, run.Tool.Driver.Rules, 3)
	assert.Equal(t, "parse-error", run.Tool.Driver.Rules[0].ID)
	assert.Equal(t, "unused-ignore", run.Tool.Driver.Rules[1].ID)
	assert.Equal(t, "unpinned-action", run.Tool.Driver.Rules[2].ID)
	assert.Equal(t, "Tags are mutable", run.Tool.Driver.Rules[2].ShortDescription.Text)

	require.Len(t, run.Results, 1)
	r := run.Results[0]
	assert.Equal(t, "unpinned-action", r.RuleID)
	assert.Equal(t, 2, r.RuleIndex)
	assert.Equal(t, "error", r.Level)
	assert.Equal(t, `"actions/checkout@v6" must be pinned to a full length commit SHA`, r.Message.Text)
	require.Len(t, r.Locations, 1)
	loc := r.Locations[0].PhysicalLocation
	assert.Equal(t, "workflow.yml", loc.ArtifactLocation.URI)
	assert.Equal(t, 8, loc.Region.StartLine)
	assert.Equal(t, 15, loc.Region.StartColumn)
}

func TestSARIFRenderer_ParseError(t *testing.T) {
	rdr := NewSARIF(nil, "1.0.0")

	tk := &token.Token{
		Value:    "bad",
		Position: &token.Position{Line: 1, Column: 1},
	}
	parseErr := &mockYAMLError{token: tk, message: "found invalid token"}
	require.NoError(t, rdr.PrintParseError("broken.yml", parseErr))

	output := captureStdout(t, func() {
		require.NoError(t, rdr.PrintSummary(1, 1, 1, 0))
	})

	var log sarifLog
	require.NoError(t, json.Unmarshal([]byte(output), &log))

	require.Len(t, log.Runs[0].Results, 1)
	r := log.Runs[0].Results[0]
	assert.Equal(t, "parse-error", r.RuleID)
	assert.Equal(t, 0, r.RuleIndex)
	assert.Equal(t, "error", r.Level)
	assert.Equal(t, "found invalid token", r.Message.Text)
}

func TestSARIFRenderer_ParseError_NonYAMLError(t *testing.T) {
	rdr := NewSARIF(nil, "")
	err := rdr.PrintParseError("file.yml", fmt.Errorf("not a yaml error"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected parse error type")
}

func TestSARIFRenderer_ParseError_InvalidToken(t *testing.T) {
	rdr := NewSARIF(nil, "")

	t.Run("nil token", func(t *testing.T) {
		parseErr := &mockYAMLError{token: nil, message: "bad"}
		err := rdr.PrintParseError("file.yml", parseErr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse error without position")
	})

	t.Run("nil position", func(t *testing.T) {
		parseErr := &mockYAMLError{token: &token.Token{Position: nil}, message: "bad"}
		err := rdr.PrintParseError("file.yml", parseErr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse error without position")
	})
}

func TestSARIFRenderer_DiagnosticError_InvalidToken(t *testing.T) {
	rdr := NewSARIF(nil, "")

	t.Run("nil token", func(t *testing.T) {
		e := &diagnostic.Error{Token: nil, RuleID: "rule", Message: "msg"}
		err := rdr.PrintDiagnosticError("file.yml", e)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "diagnostic error without position")
	})

	t.Run("nil position", func(t *testing.T) {
		e := &diagnostic.Error{Token: &token.Token{Position: nil}, RuleID: "rule", Message: "msg"}
		err := rdr.PrintDiagnosticError("file.yml", e)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "diagnostic error without position")
	})
}

func TestSARIFRenderer_MultipleResults(t *testing.T) {
	ruleList := []rules.Rule{&stubRule{id: "rule-a"}, &stubRule{id: "rule-b"}}
	rdr := NewSARIF(ruleList, "")

	for _, id := range []string{"rule-a", "rule-b", "rule-a"} {
		e := &diagnostic.Error{
			Token:   &token.Token{Value: "v", Position: &token.Position{Line: 1, Column: 1}},
			RuleID:  id,
			Message: "msg from " + id,
		}
		require.NoError(t, rdr.PrintDiagnosticError("f.yml", e))
	}

	output := captureStdout(t, func() {
		require.NoError(t, rdr.PrintSummary(1, 3, 1, 0))
	})

	var log sarifLog
	require.NoError(t, json.Unmarshal([]byte(output), &log))
	assert.Len(t, log.Runs[0].Results, 3)
}

func TestSARIFRenderer_NoResults(t *testing.T) {
	rdr := NewSARIF(nil, "1.0.0")

	output := captureStdout(t, func() {
		require.NoError(t, rdr.PrintSummary(1, 0, 0, 0))
	})

	var log sarifLog
	require.NoError(t, json.Unmarshal([]byte(output), &log))

	// results must be [] not null
	assert.NotNil(t, log.Runs[0].Results)
	assert.Empty(t, log.Runs[0].Results)

	// Verify raw JSON has "results": [] not "results": null
	assert.Contains(t, output, `"results": []`)
}

func TestSARIFRenderer_RuleIndex(t *testing.T) {
	ruleList := []rules.Rule{
		&stubRule{id: "alpha"},
		&stubRule{id: "beta"},
		&stubRule{id: "gamma"},
	}
	rdr := NewSARIF(ruleList, "")

	// Add results in reverse rule order
	for _, id := range []string{"gamma", "alpha", "beta"} {
		e := &diagnostic.Error{
			Token:   &token.Token{Value: "v", Position: &token.Position{Line: 1, Column: 1}},
			RuleID:  id,
			Message: "msg",
		}
		require.NoError(t, rdr.PrintDiagnosticError("f.yml", e))
	}

	output := captureStdout(t, func() {
		require.NoError(t, rdr.PrintSummary(1, 3, 1, 0))
	})

	var log sarifLog
	require.NoError(t, json.Unmarshal([]byte(output), &log))

	// rules: [parse-error=0, unused-ignore=1, alpha=2, beta=3, gamma=4]
	results := log.Runs[0].Results
	assert.Equal(t, 4, results[0].RuleIndex) // gamma
	assert.Equal(t, 2, results[1].RuleIndex) // alpha
	assert.Equal(t, 3, results[2].RuleIndex) // beta
}

func TestSARIFRenderer_HintIsNoOp(t *testing.T) {
	rdr := NewSARIF(nil, "")
	output := captureStdout(t, func() {
		require.NoError(t, rdr.PrintHint("some hint"))
	})
	assert.Empty(t, output)
}

func TestSARIFRenderer_RuleHelpURI(t *testing.T) {
	ruleList := []rules.Rule{&stubRule{id: "my-rule"}}
	rdr := NewSARIF(ruleList, "")

	output := captureStdout(t, func() {
		require.NoError(t, rdr.PrintSummary(0, 0, 0, 0))
	})

	var log sarifLog
	require.NoError(t, json.Unmarshal([]byte(output), &log))

	// rules[0] = parse-error (no helpUri), rules[1] = unused-ignore (has helpUri), rules[2] = my-rule (has helpUri)
	assert.Empty(t, log.Runs[0].Tool.Driver.Rules[0].HelpURI)
	assert.Equal(t, "https://github.com/koki-develop/ghasec/blob/main/rules/unused-ignore/README.md", log.Runs[0].Tool.Driver.Rules[1].HelpURI)
	assert.Equal(t, "https://github.com/koki-develop/ghasec/blob/main/rules/my-rule/README.md", log.Runs[0].Tool.Driver.Rules[2].HelpURI)
}
