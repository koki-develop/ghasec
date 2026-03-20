package invalidworkflow_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
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
	r := &invalidworkflow.Rule{}
	assert.Equal(t, "invalid-workflow", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &invalidworkflow.Rule{}
	assert.True(t, r.Required())
}

func TestRule_ValidWorkflow(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_MissingOn(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "on")
}

func TestRule_InvalidOnType(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: 123\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "on")
}

func TestRule_ValidOnTypes(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"string", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"sequence", "on: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"mapping", "on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
	}
	r := &invalidworkflow.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_MissingJobs(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestRule_EmptyJobs(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestRule_InvalidJobsType(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs: hello\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestRule_JobMissingRunsOnAndUses(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "uses")
}

func TestRule_JobHasBothRunsOnAndUses(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "uses")
}

func TestRule_JobHasBothUsesAndSteps(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    uses: org/repo/.github/workflows/ci.yml@main\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
	assert.Contains(t, errs[0].Message, "steps")
}

func TestRule_ValidReusableWorkflowJob(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_InvalidRunsOnType(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: 123\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
}

func TestRule_ValidRunsOnTypes(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"string", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"sequence", "on: push\njobs:\n  build:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: echo hi\n"},
		{"mapping", "on: push\njobs:\n  build:\n    runs-on:\n      group: my-group\n    steps:\n      - run: echo hi\n"},
	}
	r := &invalidworkflow.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_InvalidStepsType(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: not-a-sequence\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "steps")
}

func TestRule_InvalidUsesType(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: [not, a, string]\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
}

func TestRule_MultipleErrors(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "name: test\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "on")
	assert.Contains(t, errs[1].Message, "jobs")
}

func TestRule_MultipleJobErrors(t *testing.T) {
	r := &invalidworkflow.Rule{}
	src := "on: push\njobs:\n  job1:\n    steps:\n      - run: echo\n  job2:\n    runs-on: ubuntu-latest\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
}
