package rules_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseMapping(t *testing.T, src string) *ast.MappingNode {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return rules.TopLevelMapping(f.Docs[0])
}

func TestTopLevelMapping(t *testing.T) {
	f, err := yamlparser.ParseBytes([]byte("key: value"), 0)
	require.NoError(t, err)
	m := rules.TopLevelMapping(f.Docs[0])
	assert.NotNil(t, m)
}

func TestTopLevelMapping_NonMapping(t *testing.T) {
	f, err := yamlparser.ParseBytes([]byte("- item"), 0)
	require.NoError(t, err)
	m := rules.TopLevelMapping(f.Docs[0])
	assert.Nil(t, m)
}

func TestTopLevelMapping_NilBody(t *testing.T) {
	m := rules.TopLevelMapping(&ast.DocumentNode{})
	assert.Nil(t, m)
}

func TestFindKey(t *testing.T) {
	m := parseMapping(t, "foo: 1\nbar: 2")
	kv := rules.FindKey(m, "bar")
	require.NotNil(t, kv)
	assert.Equal(t, "bar", kv.Key.GetToken().Value)
}

func TestFindKey_NotFound(t *testing.T) {
	m := parseMapping(t, "foo: 1")
	kv := rules.FindKey(m, "bar")
	assert.Nil(t, kv)
}

func TestEachStep(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
  test:
    steps:
      - uses: actions/setup-go@v5`
	m := parseMapping(t, src)
	var count int
	rules.EachStep(m, func(step *ast.MappingNode) {
		count++
	})
	assert.Equal(t, 3, count)
}

func TestEachStep_NoJobs(t *testing.T) {
	m := parseMapping(t, "name: test")
	var count int
	rules.EachStep(m, func(step *ast.MappingNode) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestEachStep_NoSteps(t *testing.T) {
	src := `jobs:
  build:
    runs-on: ubuntu-latest`
	m := parseMapping(t, src)
	var count int
	rules.EachStep(m, func(step *ast.MappingNode) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestStepUsesValue(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4`
	m := parseMapping(t, src)
	var val string
	var found bool
	rules.EachStep(m, func(step *ast.MappingNode) {
		val, _, found = rules.StepUsesValue(step)
	})
	assert.True(t, found)
	assert.Equal(t, "actions/checkout@v4", val)
}

func TestStepUsesValue_NoUses(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - run: echo hello`
	m := parseMapping(t, src)
	rules.EachStep(m, func(step *ast.MappingNode) {
		_, _, found := rules.StepUsesValue(step)
		assert.False(t, found)
	})
}

func TestIsLocalAction(t *testing.T) {
	assert.True(t, rules.IsLocalAction("./my-action"))
	assert.False(t, rules.IsLocalAction("actions/checkout@v4"))
}

func TestIsDockerAction(t *testing.T) {
	assert.True(t, rules.IsDockerAction("docker://alpine:3.8"))
	assert.False(t, rules.IsDockerAction("actions/checkout@v4"))
}

func TestFirstToken(t *testing.T) {
	src := `key: value`
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m := rules.TopLevelMapping(f.Docs[0])
	tk := m.Values[0].Value.GetToken()
	first := rules.FirstToken(tk)
	assert.Equal(t, 1, len(first.Value))
}
