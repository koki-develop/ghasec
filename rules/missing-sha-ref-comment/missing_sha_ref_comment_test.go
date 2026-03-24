package missingsharefcomment_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	missingsharefcomment "github.com/koki-develop/ghasec/rules/missing-sha-ref-comment"
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

func parseActionMapping(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	require.NotEmpty(t, f.Docs)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_ID(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	assert.Equal(t, "missing-sha-ref-comment", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	assert.False(t, r.Online())
}

func TestRule_ValidRefComment(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	tests := []struct {
		name string
		uses string
	}{
		{"tag comment", "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4"},
		{"semver comment", "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2"},
		{"branch comment", "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # main"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_MissingComment(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must have an inline comment with a ref")
}

func TestRule_EmptyComment(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must have an inline comment with a ref")
}

func TestRule_InvalidRefComment(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # this is checkout\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must have an inline comment with a ref")
}

func TestRule_NotFullSHA(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	tests := []struct {
		name string
		uses string
	}{
		{"tag", "actions/checkout@v6"},
		{"branch", "actions/checkout@main"},
		{"short sha", "actions/checkout@de0fac"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_LocalAndDockerActions(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	tests := []struct {
		name string
		uses string
	}{
		{"local action", "./path/to/action"},
		{"docker action", "docker://alpine:3.8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_NoSteps(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_CheckAction_MissingComment(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must have an inline comment with a ref")
}

func TestRule_CheckAction_ValidComment(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_CheckAction_NonComposite(t *testing.T) {
	r := &missingsharefcomment.Rule{}
	src := "name: My Action\nruns:\n  using: node20\n  main: index.js\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}
