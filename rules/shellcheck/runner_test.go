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
	comments, err := r.Run(context.Background(), "bash", "echo $x\n")
	require.NoError(t, err)
	// Unquoted $x should yield at least SC2086 (and SC2154 for undefined $x).
	var hasSC2086 bool
	for _, c := range comments {
		if c.Code == 2086 {
			hasSC2086 = true
		}
	}
	assert.True(t, hasSC2086, "expected SC2086 for unquoted $x, got %+v", comments)
}

func TestExecRunner_Unavailable(t *testing.T) {
	r := &execRunner{} // empty path
	assert.False(t, r.Available())
	_, err := r.Run(context.Background(), "bash", "echo x")
	assert.ErrorIs(t, err, errUnavailable)
}
