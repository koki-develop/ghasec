package missingapptokenpermissions_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	missingapptokenpermissions "github.com/koki-develop/ghasec/rules/missing-app-token-permissions"
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

func TestRule_ID(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	assert.Equal(t, "missing-app-token-permissions", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	assert.False(t, r.Online())
}

func TestRule_SinglePermission(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@v3\n        with:\n          app-id: ${{ secrets.APP_ID }}\n          private-key: ${{ secrets.PRIVATE_KEY }}\n          permission-contents: write\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_MultiplePermissions(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@v3\n        with:\n          app-id: ${{ secrets.APP_ID }}\n          private-key: ${{ secrets.PRIVATE_KEY }}\n          permission-contents: read\n          permission-issues: write\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NoWith(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@v3\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"permission-*" input must be set in "with"`)
}

func TestRule_WithNoPermissions(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@v3\n        with:\n          app-id: ${{ secrets.APP_ID }}\n          private-key: ${{ secrets.PRIVATE_KEY }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"permission-*" input must be set in "with"`)
}

func TestRule_TokenPointsToUses(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@v3\n        with:\n          app-id: ${{ secrets.APP_ID }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "actions/create-github-app-token@v3", errs[0].Token.Value)
}

func TestRule_TokenPointsToUses_NoWith(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@v3\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "actions/create-github-app-token@v3", errs[0].Token.Value)
}

func TestRule_NonTargetAction(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_RunStepOnly(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_SHAPinned(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@f8d387b68d61c58ab83c6c016672934102569859\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"permission-*" input must be set in "with"`)
}

func TestRule_MixedSteps(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@v3\n        with:\n          app-id: ${{ secrets.APP_ID }}\n          permission-contents: write\n      - uses: actions/create-github-app-token@v3\n        with:\n          app-id: ${{ secrets.APP_ID }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
}

func TestRule_CheckAction_Missing(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: actions/create-github-app-token@v3\n      with:\n        app-id: ${{ secrets.APP_ID }}\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"permission-*" input must be set in "with"`)
}

func TestRule_CheckAction_Valid(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: actions/create-github-app-token@v3\n      with:\n        app-id: ${{ secrets.APP_ID }}\n        permission-contents: read\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_NoJobs(t *testing.T) {
	r := &missingapptokenpermissions.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}
