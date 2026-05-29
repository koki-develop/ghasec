package renderer

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	fn()
	require.NoError(t, w.Close())
	os.Stderr = old
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return string(out)
}

// refToken returns a token at a real position over a one-line source so the
// DefaultRenderer (which reads the source file) can render it.
func diagWithRef(ref string) *diagnostic.Error {
	return &diagnostic.Error{
		Token: &token.Token{
			Value:    "x",
			Position: &token.Position{Line: 1, Column: 6},
		},
		RuleID:  "shellcheck/SC2086",
		Message: "Double quote to prevent globbing and word splitting.",
		Ref:     ref,
	}
}

func TestDefaultRenderer_RefOverride(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/w.yml"
	require.NoError(t, os.WriteFile(path, []byte("run: echo $x\n"), 0o644))

	rdr := NewDefault(true)
	out := captureStderr(t, func() {
		require.NoError(t, rdr.PrintDiagnosticError(path, diagWithRef("https://www.shellcheck.net/wiki/SC2086")))
	})
	assert.Contains(t, out, "Ref: https://www.shellcheck.net/wiki/SC2086")
	assert.NotContains(t, out, "rules/shellcheck/SC2086/README.md")
}

func TestDefaultRenderer_RefDefaultWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/w.yml"
	require.NoError(t, os.WriteFile(path, []byte("run: echo $x\n"), 0o644))

	rdr := NewDefault(true)
	e := diagWithRef("")
	e.RuleID = "unpinned-action"
	out := captureStderr(t, func() {
		require.NoError(t, rdr.PrintDiagnosticError(path, e))
	})
	assert.Contains(t, out, "https://github.com/koki-develop/ghasec/blob/main/rules/unpinned-action/README.md")
}

func TestMarkdownRenderer_RefOverride(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/w.yml"
	require.NoError(t, os.WriteFile(path, []byte("run: echo $x\n"), 0o644))

	rdr := NewMarkdown(nil)
	out := captureStdout(t, func() {
		require.NoError(t, rdr.PrintDiagnosticError(path, diagWithRef("https://www.shellcheck.net/wiki/SC2086")))
	})
	assert.Contains(t, out, "- **Rule**: shellcheck/SC2086")
	assert.Contains(t, out, "- **Ref**: https://www.shellcheck.net/wiki/SC2086")
	// shellcheck findings carry no Why/Fix.
	assert.NotContains(t, out, "- **Why**:")
	assert.NotContains(t, out, "- **Fix**:")
}

func TestSARIFRenderer_DynamicDescriptorForShellcheckCode(t *testing.T) {
	// No shellcheck rule registered: the per-code ID is only known at print time.
	rdr := NewSARIF([]rules.Rule{&stubRule{id: "unpinned-action"}}, "1.0.0")
	require.NoError(t, rdr.PrintDiagnosticError("w.yml", diagWithRef("https://www.shellcheck.net/wiki/SC2086")))

	out := captureStdout(t, func() {
		require.NoError(t, rdr.PrintSummary(1, 1, 1, 0))
	})

	var log sarifLog
	require.NoError(t, json.Unmarshal([]byte(out), &log))
	run := log.Runs[0]

	require.Len(t, run.Results, 1)
	res := run.Results[0]
	assert.Equal(t, "shellcheck/SC2086", res.RuleID)
	// Must NOT collapse to index 0 (the synthetic parse-error descriptor).
	assert.NotEqual(t, 0, res.RuleIndex)

	desc := run.Tool.Driver.Rules[res.RuleIndex]
	assert.Equal(t, "shellcheck/SC2086", desc.ID)
	assert.Equal(t, "https://www.shellcheck.net/wiki/SC2086", desc.HelpURI)
	// Sanity: index 0 is still parse-error.
	assert.Equal(t, "parse-error", run.Tool.Driver.Rules[0].ID)
	assert.True(t, strings.HasPrefix(desc.HelpURI, "https://www.shellcheck.net/wiki/"))
}
