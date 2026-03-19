package renderer

import (
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findTokenByValue(src string, value string) *token.Token {
	f, _ := parser.ParseBytes([]byte(src), 0)
	if f == nil || len(f.Docs) == 0 {
		return nil
	}
	tk := f.Docs[0].Body.GetToken()
	for tk != nil {
		if tk.Value == value {
			return tk
		}
		tk = tk.Next
	}
	return nil
}

func ancestorValues(ancestors []*token.Token) []string {
	vals := make([]string, len(ancestors))
	for i, a := range ancestors {
		vals[i] = a.Value
	}
	return vals
}

func TestComputeAncestors_StepKey(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: setup\n        uses: actions/setup-go@v5\n        bogus: true"
	tk := findTokenByValue(src, "bogus")
	require.NotNil(t, tk)
	ancestors := computeAncestors(tk)
	vals := ancestorValues(ancestors)
	// "name" is a sibling of "bogus" (same column), not an ancestor
	assert.Equal(t, []string{"jobs", "build", "steps", "-"}, vals)
}

func TestComputeAncestors_TopLevelKey(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest"
	tk := findTokenByValue(src, "jobs")
	require.NotNil(t, tk)
	ancestors := computeAncestors(tk)
	assert.Empty(t, ancestors)
}

func TestComputeAncestors_DeepNesting(t *testing.T) {
	src := "on:\n  workflow_dispatch:\n    inputs:\n      myinput:\n        description: test\n        unknown_prop: value"
	tk := findTokenByValue(src, "unknown_prop")
	require.NotNil(t, tk)
	ancestors := computeAncestors(tk)
	vals := ancestorValues(ancestors)
	// "description" is a sibling, not an ancestor
	assert.Equal(t, []string{"on", "workflow_dispatch", "inputs", "myinput"}, vals)
}

func TestComputeAncestors_SequenceEntry(t *testing.T) {
	src := "on:\n  schedule:\n    - cron: '0 0 * * *'\n    - foo: bar"
	tk := findTokenByValue(src, "foo")
	require.NotNil(t, tk)
	ancestors := computeAncestors(tk)
	vals := ancestorValues(ancestors)
	assert.Equal(t, []string{"on", "schedule", "-"}, vals)
}

func TestComputeAncestors_NilToken(t *testing.T) {
	ancestors := computeAncestors(nil)
	assert.Nil(t, ancestors)
}

func TestComputeAncestors_ValueToken(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4"
	tk := findTokenByValue(src, "actions/checkout@v4")
	require.NotNil(t, tk)
	ancestors := computeAncestors(tk)
	vals := ancestorValues(ancestors)
	assert.Contains(t, vals, "jobs")
	assert.Contains(t, vals, "build")
	assert.Contains(t, vals, "steps")
	assert.Contains(t, vals, "-")
}

func TestComputeAncestors_MultipleSteps(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: first\n        run: echo first\n        bogus1: a\n      - name: second\n        run: echo second\n        bogus2: b"
	// Second step's error should find second step's `-`, not the first
	tk := findTokenByValue(src, "bogus2")
	require.NotNil(t, tk)
	ancestors := computeAncestors(tk)
	vals := ancestorValues(ancestors)
	assert.Equal(t, []string{"jobs", "build", "steps", "-"}, vals)
	// Verify the `-` is for the second step (line should be after the first step)
	for _, a := range ancestors {
		if a.Value == "-" {
			// The second `-` should be on line 9 (1-indexed)
			assert.Equal(t, 9, a.Position.Line)
		}
	}
}
