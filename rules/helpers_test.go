package rules_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/rules"
	"github.com/stretchr/testify/assert"
)

func dummyToken() *token.Token {
	return token.New("test", "test", &token.Position{})
}

func TestUnwrapNode_Nil(t *testing.T) {
	assert.Nil(t, rules.UnwrapNode(nil))
}

func TestUnwrapNode_Regular(t *testing.T) {
	n := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	assert.Equal(t, n, rules.UnwrapNode(n))
}

func TestUnwrapNode_Anchor(t *testing.T) {
	inner := &ast.MappingNode{BaseNode: &ast.BaseNode{}, Start: dummyToken()}
	anchor := &ast.AnchorNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: inner}
	assert.Equal(t, inner, rules.UnwrapNode(anchor))
}

func TestUnwrapNode_Alias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	// AliasNode is NOT unwrapped — returned as-is
	assert.Equal(t, alias, rules.UnwrapNode(alias))
}

func TestIsMapping_Anchor(t *testing.T) {
	inner := &ast.MappingNode{BaseNode: &ast.BaseNode{}, Start: dummyToken()}
	anchor := &ast.AnchorNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: inner}
	assert.True(t, rules.IsMapping(anchor))
}

func TestIsMapping_Alias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	assert.True(t, rules.IsMapping(alias))
}

func TestIsSequence_Anchor(t *testing.T) {
	inner := &ast.SequenceNode{BaseNode: &ast.BaseNode{}, Start: dummyToken()}
	anchor := &ast.AnchorNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: inner}
	assert.True(t, rules.IsSequence(anchor))
}

func TestIsSequence_Alias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	assert.True(t, rules.IsSequence(alias))
}

func TestIsString_Anchor(t *testing.T) {
	inner := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	anchor := &ast.AnchorNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: inner}
	assert.True(t, rules.IsString(anchor))
}

func TestIsString_Alias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	assert.True(t, rules.IsString(alias))
}

func TestNodeTypeName_Anchor(t *testing.T) {
	inner := &ast.MappingNode{BaseNode: &ast.BaseNode{}, Start: dummyToken()}
	anchor := &ast.AnchorNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: inner}
	assert.Equal(t, "mapping", rules.NodeTypeName(anchor))
}

func TestNodeTypeName_Alias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	assert.Equal(t, "alias", rules.NodeTypeName(alias))
}

func TestIsNull_Alias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	// Alias is NOT null
	assert.False(t, rules.IsNull(alias))
}
