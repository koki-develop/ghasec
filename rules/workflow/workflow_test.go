package workflow_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/rules/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseYAML(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
}

func TestRule_ID(t *testing.T) {
	r := &workflow.Rule{}
	assert.Equal(t, "workflow", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &workflow.Rule{}
	assert.True(t, r.Required())
}

func TestRule_ValidWorkflow(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_EmptyDocument(t *testing.T) {
	r := &workflow.Rule{}
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	errs := r.Check(f)
	require.Len(t, errs, 2)
	assert.Equal(t, "\"on\" is required", errs[0].Message)
	assert.Equal(t, "\"jobs\" is required", errs[1].Message)
}

func TestRule_NonMappingDocument(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "- item1\n- item2\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestRule_MissingOn(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "on")
}

func TestRule_InvalidOnType(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: 123\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(f)
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
	r := &workflow.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseYAML(t, tt.src)
			errs := r.Check(f)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_MissingJobs(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestRule_EmptyJobs(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestRule_InvalidJobsType(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs: hello\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestRule_JobMissingRunsOnAndUses(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "uses")
}

func TestRule_JobHasBothRunsOnAndUses(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "uses")
}

func TestRule_JobHasBothUsesAndSteps(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  build:\n    uses: org/repo/.github/workflows/ci.yml@main\n    steps:\n      - run: echo hi\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
	assert.Contains(t, errs[0].Message, "steps")
}

func TestRule_ValidReusableWorkflowJob(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_InvalidRunsOnType(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: 123\n    steps:\n      - run: echo hi\n")
	errs := r.Check(f)
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
	r := &workflow.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseYAML(t, tt.src)
			errs := r.Check(f)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_InvalidStepsType(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: not-a-sequence\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "steps")
}

func TestRule_InvalidUsesType(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  call:\n    uses: [not, a, string]\n")
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
}

func TestRule_MultipleErrors(t *testing.T) {
	r := &workflow.Rule{}
	f := parseYAML(t, "name: test\n")
	errs := r.Check(f)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "on")
	assert.Contains(t, errs[1].Message, "jobs")
}

func TestRule_MultipleJobErrors(t *testing.T) {
	r := &workflow.Rule{}
	src := "on: push\njobs:\n  job1:\n    steps:\n      - run: echo\n  job2:\n    runs-on: ubuntu-latest\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 2)
}
