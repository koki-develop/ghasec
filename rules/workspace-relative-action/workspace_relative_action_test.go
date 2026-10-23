package workspacerelativeaction_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	workspacerelativeaction "github.com/koki-develop/ghasec/rules/workspace-relative-action"
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

func workflowWithStepUses(uses string) string {
	return "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + uses + "\n"
}

func actionWithStepUses(uses string) string {
	return "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: " + uses + "\n"
}

func TestRule_ID(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	assert.Equal(t, "workspace-relative-action", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	assert.False(t, r.Online())
}

func TestRule_WorkspaceRelative(t *testing.T) {
	tests := []struct {
		uses    string
		wantMsg string
	}{
		{"./.github/actions/build", `"./.github/actions/build" must be referenced as "$/.github/actions/build"`},
		{"./my-action", `"./my-action" must be referenced as "$/my-action"`},
		{"./", `"./" must be referenced as "$/"`},
	}
	r := &workspacerelativeaction.Rule{}
	for _, tt := range tests {
		t.Run(tt.uses, func(t *testing.T) {
			errs := r.CheckWorkflow(parseMapping(t, workflowWithStepUses(tt.uses)))
			require.Len(t, errs, 1)
			assert.Equal(t, tt.wantMsg, errs[0].Message)

			errs = r.CheckAction(parseActionMapping(t, actionWithStepUses(tt.uses)))
			require.Len(t, errs, 1)
			assert.Equal(t, tt.wantMsg, errs[0].Message)
		})
	}
}

func TestRule_NotWorkspaceRelative(t *testing.T) {
	tests := []string{
		"$/.github/actions/build",
		"$/",
		"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"actions/checkout@v6",
		"docker://alpine:3.8",
	}
	r := &workspacerelativeaction.Rule{}
	for _, uses := range tests {
		t.Run(uses, func(t *testing.T) {
			assert.Empty(t, r.CheckWorkflow(parseMapping(t, workflowWithStepUses(uses))))
			assert.Empty(t, r.CheckAction(parseActionMapping(t, actionWithStepUses(uses))))
		})
	}
}

func TestRule_RunStep(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./build.sh\n"
	assert.Empty(t, r.CheckWorkflow(parseMapping(t, src)))
}

func TestRule_LocalReusableWorkflowJob(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	src := "on: push\njobs:\n  call:\n    uses: ./.github/workflows/ci.yml\n"
	assert.Empty(t, r.CheckWorkflow(parseMapping(t, src)))
}

func TestRule_NonCompositeAction(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	src := "name: test\ndescription: test\nruns:\n  using: node24\n  main: index.js\n"
	assert.Empty(t, r.CheckAction(parseActionMapping(t, src)))
}

func TestRule_MultipleSteps(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./one\n      - uses: $/two\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./three\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
	assert.Equal(t, `"./one" must be referenced as "$/one"`, errs[0].Message)
	assert.Equal(t, `"./three" must be referenced as "$/three"`, errs[1].Message)
}

func TestRule_TokenPosition(t *testing.T) {
	r := &workspacerelativeaction.Rule{}
	errs := r.CheckWorkflow(parseMapping(t, workflowWithStepUses("./my-action")))
	require.Len(t, errs, 1)
	require.NotNil(t, errs[0].Token)
	assert.Equal(t, 6, errs[0].Token.Position.Line)
	assert.Equal(t, 15, errs[0].Token.Position.Column)
	assert.Equal(t, "./my-action", errs[0].Token.Value)
}
