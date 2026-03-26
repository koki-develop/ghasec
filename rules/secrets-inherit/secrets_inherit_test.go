package secretsinherit_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	secretsinherit "github.com/koki-develop/ghasec/rules/secrets-inherit"
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
	r := &secretsinherit.Rule{}
	assert.Equal(t, "secrets-inherit", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &secretsinherit.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &secretsinherit.Rule{}
	assert.False(t, r.Online())
}

func TestRule_NoJobs(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_SecretsInherit(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets: inherit\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "job \"call\" must not use `secrets: inherit`", errs[0].Message)
	assert.Equal(t, "inherit", errs[0].Token.Value)
}

func TestRule_ExplicitSecrets(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets:\n      token: ${{ secrets.GITHUB_TOKEN }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NoSecrets(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_MultipleJobsMixed(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call1:\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets:\n      token: ${{ secrets.GITHUB_TOKEN }}\n  call2:\n    uses: org/repo/.github/workflows/deploy.yml@main\n    secrets: inherit\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "job \"call2\" must not use `secrets: inherit`", errs[0].Message)
}

func TestRule_MultipleJobsAllInherit(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call1:\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets: inherit\n  call2:\n    uses: org/repo/.github/workflows/deploy.yml@main\n    secrets: inherit\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Equal(t, "inherit", errs[0].Token.Value)
	assert.Equal(t, "inherit", errs[1].Token.Value)
}

func TestRule_NonMappingJobValue(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build: invalid\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_AnchoredJobMapping(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call: &call\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets: inherit\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "secrets: inherit")
}

func TestRule_NullSecrets(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets:\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_EmptySecretsMapping(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets: {}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_TokenPosition(t *testing.T) {
	r := &secretsinherit.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n    secrets: inherit\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, 6, errs[0].Token.Position.Line)
	assert.Equal(t, 14, errs[0].Token.Position.Column)
}
