package unpinnedaction_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseMapping(t *testing.T, src string) workflow.WorkflowMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	require.NotEmpty(t, f.Docs)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_ID(t *testing.T) {
	r := &unpinnedaction.Rule{}
	assert.Equal(t, "unpinned-action", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &unpinnedaction.Rule{}
	assert.False(t, r.Required())
}

func TestRule_PinnedToFullSHA(t *testing.T) {
	r := &unpinnedaction.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_NotPinned(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"tag", "actions/checkout@v6"},
		{"branch", "actions/checkout@main"},
		{"short sha", "actions/checkout@de0fac"},
		{"no ref", "actions/checkout"},
	}
	r := &unpinnedaction.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.Check(m)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "pinned to a full length commit SHA")
		})
	}
}

func TestRule_LocalAndDockerActions(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"local action", "./path/to/action"},
		{"docker action", "docker://alpine:3.8"},
	}
	r := &unpinnedaction.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.Check(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_NoSteps(t *testing.T) {
	r := &unpinnedaction.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}
