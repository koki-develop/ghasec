package shellcheck

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeShell(t *testing.T) {
	cases := []struct {
		raw    string
		wantSh string
		wantOK bool
	}{
		{"bash", "bash", true},
		{"sh", "sh", true},
		{"bash -e {0}", "bash", true},
		{"sh -eu {0}", "sh", true},
		{"pwsh -Command {0}", "", false},
		{"pwsh", "", false},
		{"powershell", "", false},
		{"python", "", false},
		{"cmd", "", false},
		{"", "", false},
		{"   ", "", false},
	}
	for _, c := range cases {
		sh, ok := normalizeShell(c.raw)
		assert.Equal(t, c.wantOK, ok, "raw=%q", c.raw)
		assert.Equal(t, c.wantSh, sh, "raw=%q", c.raw)
	}
}

// runsOnNode parses a "runs-on: <value>" fragment and returns the value node.
func runsOnNode(t *testing.T, value string) ast.Node {
	t.Helper()
	if value == "" {
		return nil
	}
	f, err := yamlparser.ParseBytes([]byte("runs-on: "+value+"\n"), 0)
	require.NoError(t, err)
	m := f.Docs[0].Body.(*ast.MappingNode)
	return m.Values[0].Value
}

func TestIsWindowsOnly(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"windows-latest", true},
		{"windows-2022", true},
		{"ubuntu-latest", false},
		{"macos-latest", false},
		{"self-hosted", false},
		{"${{ matrix.os }}", false},
		{"[self-hosted, windows]", true},
		{"[self-hosted, linux]", false},
		{"[windows-latest, ubuntu-latest]", false},
		{"[self-hosted, windows, x64]", true},
		{"[self-hosted, '${{ matrix.x }}']", false},
	}
	for _, c := range cases {
		got := isWindowsOnly(runsOnNode(t, c.value))
		assert.Equal(t, c.want, got, "runs-on=%q", c.value)
	}
	// nil runs-on (absent) is not windows-only.
	assert.False(t, isWindowsOnly(nil))
}

func TestResolveWorkflowTarget(t *testing.T) {
	// Explicit bash/sh: target regardless of runs-on.
	sh, target := resolveWorkflowTarget("bash", true, runsOnNode(t, "windows-latest"))
	assert.True(t, target)
	assert.Equal(t, "bash", sh)

	sh, target = resolveWorkflowTarget("sh -e {0}", true, nil)
	assert.True(t, target)
	assert.Equal(t, "sh", sh)

	// Explicit non-shell: skip.
	_, target = resolveWorkflowTarget("pwsh", true, runsOnNode(t, "ubuntu-latest"))
	assert.False(t, target)

	// Unspecified + non-windows: bash.
	sh, target = resolveWorkflowTarget("", false, runsOnNode(t, "ubuntu-latest"))
	assert.True(t, target)
	assert.Equal(t, "bash", sh)

	// Unspecified + windows-only: skip.
	_, target = resolveWorkflowTarget("", false, runsOnNode(t, "windows-latest"))
	assert.False(t, target)

	// Unspecified + matrix expression: bash (unresolvable → analyze).
	sh, target = resolveWorkflowTarget("", false, runsOnNode(t, "${{ matrix.os }}"))
	assert.True(t, target)
	assert.Equal(t, "bash", sh)
}
