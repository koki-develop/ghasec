package shellcheck

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseComments(t *testing.T) {
	data := []byte(`{"comments":[
		{"file":"-","line":1,"endLine":1,"column":6,"endColumn":8,"level":"info","code":2086,"message":"Double quote to prevent globbing and word splitting."}
	]}`)
	comments, err := parseComments(data)
	require.NoError(t, err)
	require.Len(t, comments, 1)
	assert.Equal(t, 1, comments[0].Line)
	assert.Equal(t, 6, comments[0].Column)
	assert.Equal(t, 8, comments[0].EndColumn)
	assert.Equal(t, "info", comments[0].Level)
	assert.Equal(t, 2086, comments[0].Code)
	assert.Contains(t, comments[0].Message, "Double quote")
}

func TestParseComments_Empty(t *testing.T) {
	comments, err := parseComments([]byte(`{"comments":[]}`))
	require.NoError(t, err)
	assert.Empty(t, comments)

	comments, err = parseComments([]byte(""))
	require.NoError(t, err)
	assert.Empty(t, comments)
}

func TestExecRunner_Smoke(t *testing.T) {
	r := NewExecRunner()
	if !r.Available() {
		t.Skip("shellcheck not installed")
	}
	batched, err := r.RunBatch(context.Background(), "bash", []string{"echo $x\n"})
	require.NoError(t, err)
	require.Len(t, batched, 1)
	comments := batched[0]
	// Unquoted $x yields SC2086. SC2154 (referenced but not assigned) must be
	// excluded via -e, since Actions variables are defined outside the script.
	var hasSC2086, hasSC2154 bool
	for _, c := range comments {
		switch c.Code {
		case 2086:
			hasSC2086 = true
		case 2154:
			hasSC2154 = true
		}
	}
	assert.True(t, hasSC2086, "expected SC2086 for unquoted $x, got %+v", comments)
	assert.False(t, hasSC2154, "SC2154 must be excluded, got %+v", comments)
}

// TestExecRunner_BatchDemux verifies that a multi-script batch invocation maps
// findings back to the correct script index: only the first script has an
// unquoted expansion (SC2086), the second is clean.
func TestExecRunner_BatchDemux(t *testing.T) {
	r := NewExecRunner()
	if !r.Available() {
		t.Skip("shellcheck not installed")
	}
	batched, err := r.RunBatch(context.Background(), "bash", []string{"echo $x\n", "echo hello\n"})
	require.NoError(t, err)
	require.Len(t, batched, 2)

	var firstHasSC2086 bool
	for _, c := range batched[0] {
		if c.Code == 2086 {
			firstHasSC2086 = true
		}
	}
	assert.True(t, firstHasSC2086, "expected SC2086 in first script, got %+v", batched[0])
	assert.Empty(t, batched[1], "clean second script must have no findings, got %+v", batched[1])
}

func TestExecRunner_Unavailable(t *testing.T) {
	r := &execRunner{} // empty path
	assert.False(t, r.Available())
	_, err := r.Run(context.Background(), "bash", "echo x")
	assert.ErrorIs(t, err, errUnavailable)
	_, err = r.RunBatch(context.Background(), "bash", []string{"echo x"})
	assert.ErrorIs(t, err, errUnavailable)
}
