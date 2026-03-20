package joballpermissions_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	joballpermissions "github.com/koki-develop/ghasec/rules/job-all-permissions"
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
	r := &joballpermissions.Rule{}
	assert.Equal(t, "job-all-permissions", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &joballpermissions.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &joballpermissions.Rule{}
	assert.False(t, r.Online())
}

func TestRule_NoJobs(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_WorkflowLevelWriteAllIgnored(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_JobWithoutPermissions(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_JobWithScopedPermissions(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_JobWithEmptyPermissions(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_JobWithReadAll(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: read-all\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"permissions" must not be "read-all"; grant individual scopes instead`, errs[0].Message)
	assert.Equal(t, "read-all", errs[0].Token.Value)
}

func TestRule_JobWithWriteAll(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: write-all\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"permissions" must not be "write-all"; grant individual scopes instead`, errs[0].Message)
	assert.Equal(t, "write-all", errs[0].Token.Value)
}

func TestRule_MultipleJobsWithAllPermissions(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: read-all\n    steps:\n      - run: echo hi\n  deploy:\n    runs-on: ubuntu-latest\n    permissions: write-all\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "read-all")
	assert.Contains(t, errs[1].Message, "write-all")
}

func TestRule_JobWithQuotedReadAll(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: \"read-all\"\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "read-all")
}

func TestRule_JobWithQuotedWriteAll(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: 'write-all'\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "write-all")
}

func TestRule_JobWithNullPermissions(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_TokenPosition(t *testing.T) {
	r := &joballpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: read-all\n    steps:\n      - run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, 6, errs[0].Token.Position.Line)
}
