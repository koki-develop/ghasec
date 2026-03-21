package jobtimeoutminutes_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	jobtimeoutminutes "github.com/koki-develop/ghasec/rules/job-timeout-minutes"
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
	r := &jobtimeoutminutes.Rule{}
	assert.Equal(t, "job-timeout-minutes", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	assert.False(t, r.Online())
}

func TestRule_NoJobs(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_JobWithTimeoutMinutes(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_JobMissingTimeoutMinutes(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"timeout-minutes" must be set`, errs[0].Message)
	assert.Equal(t, "build", errs[0].Token.Value)
}

func TestRule_MultipleJobsMixed(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n    steps:\n      - run: echo hi\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"timeout-minutes" must be set`, errs[0].Message)
	assert.Equal(t, "deploy", errs[0].Token.Value)
}

func TestRule_MultipleJobsAllMissing(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Equal(t, "build", errs[0].Token.Value)
	assert.Equal(t, "deploy", errs[1].Token.Value)
}

func TestRule_ReusableWorkflowCallSkipped(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_MixedNormalAndReusableJobs(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "build", errs[0].Token.Value)
}

func TestRule_NonMappingJobValue(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build: invalid\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_TokenPosition(t *testing.T) {
	r := &jobtimeoutminutes.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, 4, errs[0].Token.Position.Line)
	assert.Equal(t, 3, errs[0].Token.Position.Column)
}
