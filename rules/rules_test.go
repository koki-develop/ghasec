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
