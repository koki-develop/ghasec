package invalidexpression

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseWorkflow(t *testing.T, src string) workflow.WorkflowMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func parseAction(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_ID(t *testing.T) {
	r := &Rule{}
	assert.Equal(t, "invalid-expression", r.ID())
	assert.False(t, r.Required())
	assert.False(t, r.Online())
}

func TestRule_ValidExpressions(t *testing.T) {
	r := &Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.actor }}\n      - if: github.event_name == 'push'\n        run: echo push\n      - run: ${{ format('hello {0}', 'world') }}\n"
	m := parseWorkflow(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_SyntaxErrors(t *testing.T) {
	r := &Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event == }}\n"
	m := parseWorkflow(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "invalid expression syntax")
}

func TestRule_BareIfSyntaxError(t *testing.T) {
	r := &Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event ==\n        run: echo test\n"
	m := parseWorkflow(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "invalid expression syntax")
}

func TestRule_UnterminatedExpression(t *testing.T) {
	r := &Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ hello\n"
	m := parseWorkflow(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "invalid expression syntax")
}

func TestRule_BareIfBlockScalar(t *testing.T) {
	r := &Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n        if: |\n          success() =="
	m := parseWorkflow(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "invalid expression syntax")
	// The error token must point to the block scalar content line, not the | indicator line.
	// "if: |" is on line 7, content "success() ==" is on line 8.
	assert.Equal(t, 8, errs[0].Token.Position.Line)
}

func TestRule_ActionSyntaxError(t *testing.T) {
	r := &Rule{}
	src := "name: Test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - run: echo ${{ contains( }}\n"
	m := parseAction(t, src)
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "invalid expression syntax")
}
