package invalidaction_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	invalidaction "github.com/koki-develop/ghasec/rules/invalid-action"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseMapping(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	require.NotEmpty(t, f.Docs)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_UnknownTopLevelKey(t *testing.T) {
	r := &invalidaction.Rule{}
	m := parseMapping(t, "name: my-action\ndescription: test\nfoo: bar\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_AllKnownTopLevelKeysAccepted(t *testing.T) {
	r := &invalidaction.Rule{}
	m := parseMapping(t, "name: my-action\ndescription: test\nauthor: me\ninputs:\n  token:\n    description: token\noutputs:\n  result:\n    description: result\nruns:\n  using: node20\n  main: index.js\nbranding:\n  icon: check\n  color: green\n")
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_RunsMissing(t *testing.T) {
	r := &invalidaction.Rule{}
	m := parseMapping(t, "name: my-action\ndescription: test\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs")
	assert.Contains(t, errs[0].Message, "is required")
}
