package scriptinjection_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	scriptinjection "github.com/koki-develop/ghasec/rules/script-injection"
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
	r := &scriptinjection.Rule{}
	assert.Equal(t, "script-injection", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &scriptinjection.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &scriptinjection.Rule{}
	assert.False(t, r.Online())
}

func TestRule_RunWithExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"run" must not contain expressions; use environment variables instead`, errs[0].Message)
	assert.Equal(t, "${{ github.event.issue.title }}", errs[0].Token.Value)
}

func TestRule_RunWithMultipleExpressions(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.actor }} ${{ github.token }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Equal(t, "${{ github.actor }}", errs[0].Token.Value)
	assert.Equal(t, "${{ github.token }}", errs[1].Token.Value)
}

func TestRule_RunWithoutExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_RunWithEnvVar(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo $TITLE\n        env:\n          TITLE: ${{ github.event.issue.title }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_IfWithExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: ${{ success() }}\n        run: echo ok\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_EnvWithExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo $FOO\n        env:\n          FOO: ${{ github.token }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_GitHubScriptWithExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.token }}')\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"script" must not contain expressions; use environment variables instead`, errs[0].Message)
	assert.Equal(t, "${{ github.token }}", errs[0].Token.Value)
}

func TestRule_GitHubScriptWithoutExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('hello')\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NonGitHubScriptWithExpressionInWith(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-go@v5\n        with:\n          go-version: ${{ matrix.go }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_GitHubScriptPinnedSHA(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          script: console.log('${{ github.token }}')\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"script" must not contain expressions; use environment variables instead`, errs[0].Message)
}

func TestRule_CheckAction_RunWithExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - run: echo ${{ github.token }}\n      shell: bash\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"run" must not contain expressions; use environment variables instead`, errs[0].Message)
}

func TestRule_CheckAction_RunWithoutExpression(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - run: echo hello\n      shell: bash\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_CheckAction_NonComposite(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "name: My Action\nruns:\n  using: node20\n  main: index.js\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_GitHubScriptNoWith(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_GitHubScriptWithNoScript(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          result-encoding: string\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_GitHubScriptCaseInsensitive(t *testing.T) {
	r := &scriptinjection.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: Actions/GitHub-Script@v7\n        with:\n          script: console.log('${{ github.token }}')\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"script" must not contain expressions; use environment variables instead`, errs[0].Message)
}
