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

func TestRule_InvalidJobsType(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs: hello\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestRule_ValidReusableWorkflowJob(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_ValidLocalReusableWorkflowJob(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: ./.github/workflows/ci.yml\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_ReusableWorkflowJobMissingRef(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must have a ref")
}

func TestRule_ReusableWorkflowJobDockerReference(t *testing.T) {
	tests := []string{
		"docker://registry/img/wf.yml",
		"docker://registry/img/wf.yml@v1",
	}
	r := &invalidworkflow.Rule{}
	for _, uses := range tests {
		t.Run(uses, func(t *testing.T) {
			errs := r.CheckWorkflow(parseMapping(t, "on: push\njobs:\n  call:\n    uses: "+uses+"\n"))
			require.Len(t, errs, 1)
			assert.Equal(t, `"uses" must be a reusable workflow reference, but got a Docker image`, errs[0].Message)
		})
	}
}

func TestRule_SelfRepositoryUses(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMsg string
	}{
		{
			name: "step without ref",
			src:  "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: $/.github/actions/build\n",
		},
		{
			name: "step repository root",
			src:  "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: $/\n",
		},
		{
			name: "job without ref",
			src:  "on: push\njobs:\n  call:\n    uses: $/.github/workflows/ci.yml\n",
		},
		{
			name:    "step with ref",
			src:     "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: $/.github/actions/build@v1\n",
			wantMsg: `"$/.github/actions/build@v1" must not have a ref`,
		},
		{
			name:    "job with ref",
			src:     "on: push\njobs:\n  call:\n    uses: $/.github/workflows/ci.yml@main\n",
			wantMsg: `"$/.github/workflows/ci.yml@main" must not have a ref`,
		},
	}
	r := &invalidworkflow.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := r.CheckWorkflow(parseMapping(t, tt.src))
			if tt.wantMsg == "" {
				assert.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1)
			assert.Equal(t, tt.wantMsg, errs[0].Message)
		})
	}
}

func TestRule_MultipleErrors(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "name: test\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "on")
	assert.Contains(t, errs[1].Message, "jobs")
}
