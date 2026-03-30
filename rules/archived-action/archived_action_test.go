package archivedaction_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	archivedaction "github.com/koki-develop/ghasec/rules/archived-action"
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

type mockChecker struct {
	results map[string]bool // "owner/repo" -> archived
	err     error
}

func (m *mockChecker) IsArchived(_ context.Context, owner, repo string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	key := fmt.Sprintf("%s/%s", owner, repo)
	return m.results[key], nil
}

func TestRule_ID(t *testing.T) {
	r := &archivedaction.Rule{}
	assert.Equal(t, "archived-action", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &archivedaction.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &archivedaction.Rule{}
	assert.True(t, r.Online())
}

func TestRule_Archived(t *testing.T) {
	r := &archivedaction.Rule{
		Checker: &mockChecker{
			results: map[string]bool{
				"archived-org/archived-repo": true,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: archived-org/archived-repo@v1\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"archived-org/archived-repo" is archived and must not be used`)
}

func TestRule_NotArchived(t *testing.T) {
	r := &archivedaction.Rule{
		Checker: &mockChecker{
			results: map[string]bool{
				"active-org/active-repo": false,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: active-org/active-repo@v1\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_CheckerError(t *testing.T) {
	r := &archivedaction.Rule{
		Checker: &mockChecker{err: fmt.Errorf("network error")},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: some-org/some-repo@v1\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "failed to check archive status")
	assert.Contains(t, errs[0].Message, "network error")
}

func TestRule_LocalAction(t *testing.T) {
	r := &archivedaction.Rule{Checker: &mockChecker{}}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./local-action\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_DockerAction(t *testing.T) {
	r := &archivedaction.Rule{Checker: &mockChecker{}}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://alpine:3.8\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_TokenPosition(t *testing.T) {
	r := &archivedaction.Rule{
		Checker: &mockChecker{
			results: map[string]bool{
				"archived-org/archived-repo": true,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: archived-org/archived-repo@v1\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Equal(t, "archived-org/archived-repo@v1", errs[0].Token.Value)
}

func TestRule_MultipleSteps(t *testing.T) {
	r := &archivedaction.Rule{
		Checker: &mockChecker{
			results: map[string]bool{
				"archived-org/repo-a": true,
				"archived-org/repo-b": true,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: archived-org/repo-a@v1\n      - uses: archived-org/repo-b@v2\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "archived-org/repo-a")
	assert.Contains(t, errs[1].Message, "archived-org/repo-b")
}

func TestRule_CheckAction(t *testing.T) {
	r := &archivedaction.Rule{
		Checker: &mockChecker{
			results: map[string]bool{
				"archived-org/archived-repo": true,
			},
		},
	}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: archived-org/archived-repo@v1\n"
	errs := r.CheckAction(parseActionMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "is archived and must not be used")
}

func TestRule_CheckAction_NonComposite(t *testing.T) {
	r := &archivedaction.Rule{Checker: &mockChecker{}}
	src := "name: My Action\nruns:\n  using: node20\n  main: index.js\n"
	errs := r.CheckAction(parseActionMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_SubdirAction(t *testing.T) {
	r := &archivedaction.Rule{
		Checker: &mockChecker{
			results: map[string]bool{
				"google-github-actions/auth": true,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: google-github-actions/auth/cleanup@v1\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "google-github-actions/auth")
}

func TestRule_NoSteps(t *testing.T) {
	r := &archivedaction.Rule{Checker: &mockChecker{}}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}
