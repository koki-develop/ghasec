package unpinnedcontainer_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	unpinnedcontainer "github.com/koki-develop/ghasec/rules/unpinned-container"
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
	r := &unpinnedcontainer.Rule{}
	assert.Equal(t, "unpinned-container", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	assert.False(t, r.Online())
}

func TestRule_ContainerStringPinned(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: ubuntu@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_ContainerStringUnpinned(t *testing.T) {
	tests := []struct {
		name  string
		image string
	}{
		{"tag", "ubuntu:22.04"},
		{"no tag", "ubuntu"},
		{"registry with tag", "ghcr.io/owner/repo:latest"},
		{"registry no tag", "ghcr.io/owner/repo"},
	}
	r := &unpinnedcontainer.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: " + tt.image + "\n    steps:\n      - run: echo hi\n"
			errs := r.CheckWorkflow(parseMapping(t, src))
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "pinned to a digest")
		})
	}
}

func TestRule_ContainerMappingPinned(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container:\n      image: ubuntu@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_ContainerMappingUnpinned(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container:\n      image: ubuntu:22.04\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "pinned to a digest")
}

func TestRule_ServiceImagePinned(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    services:\n      redis:\n        image: redis@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_ServiceImageUnpinned(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    services:\n      redis:\n        image: redis:7\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "pinned to a digest")
}

func TestRule_MultipleServicesUnpinned(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    services:\n      redis:\n        image: redis:7\n      postgres:\n        image: postgres:16\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_ContainerAndServicesUnpinned(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: ubuntu:22.04\n    services:\n      redis:\n        image: redis:7\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_ContainerExpressionSkipped(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: ${{ inputs.image }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_ServiceImageExpressionSkipped(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    services:\n      redis:\n        image: ${{ inputs.redis_image }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_ContainerMappingExpressionSkipped(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container:\n      image: ${{ inputs.image }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_NoContainerOrServices(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_ContainerTagPlusDigest(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: ubuntu:22.04@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_MultipleJobsWithContainers(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: ubuntu:22.04\n    steps:\n      - run: echo hi\n  test:\n    runs-on: ubuntu-latest\n    container: node:20\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_ReusableWorkflowJobSkipped(t *testing.T) {
	r := &unpinnedcontainer.Rule{}
	src := "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}
