package unpinnedreusableworkflow_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	unpinnedreusableworkflow "github.com/koki-develop/ghasec/rules/unpinned-reusable-workflow"
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
	r := &unpinnedreusableworkflow.Rule{}
	assert.Equal(t, "unpinned-reusable-workflow", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	assert.False(t, r.Online())
}

func TestRule_PinnedToFullSHA(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NotPinned(t *testing.T) {
	tests := []struct {
		name string
		ref  string
	}{
		{"tag", "v1.0.0"},
		{"branch", "main"},
		{"slash branch", "release/v1"},
		{"short sha", "de0fac2"},
		{"39-char hex", "de0fac2e4500dabe0009e67214ff5f5447ce83d"},
		{"41-char hex", "de0fac2e4500dabe0009e67214ff5f5447ce83dde"},
		{"uppercase hex", "DE0FAC2E4500DABE0009E67214FF5F5447CE83DD"},
		{"mixed-case hex", "De0fAc2e4500dabe0009e67214ff5f5447ce83dd"},
		{"non-hex 40 chars", "ge0fac2e4500dabe0009e67214ff5f5447ce83dd"},
	}
	r := &unpinnedreusableworkflow.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@%s\n", tt.ref)
			m := parseMapping(t, src)
			errs := r.CheckWorkflow(m)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "must be pinned to a full length commit SHA")
		})
	}
}

func TestRule_LocalReusableWorkflow(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  call:\n    uses: ./.github/workflows/ci.yml\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_StepOnlyJobs(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v6\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NoUsesKey(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  empty:\n    runs-on: ubuntu-latest\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NoRef(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_ExpressionInRef(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@${{ env.REF }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must be pinned to a full length commit SHA")
}

func TestRule_MultipleJobsMixed(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  pinned:\n    uses: org/repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n  unpinned:\n    uses: org/repo/.github/workflows/deploy.yml@main\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "deploy.yml@main")
}

func TestRule_AnchoredJobMapping(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  call: &call\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must be pinned to a full length commit SHA")
}

func TestRule_TokenPosition(t *testing.T) {
	r := &unpinnedreusableworkflow.Rule{}
	src := "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, 4, errs[0].Token.Position.Line)
	assert.Equal(t, 11+33+1, errs[0].Token.Position.Column)
	assert.Equal(t, "main", errs[0].Token.Value)
}
