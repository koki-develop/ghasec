package rules_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestIsAliasNode_Alias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	assert.True(t, rules.IsAliasNode(alias))
}

func TestIsAliasNode_AnchorWrappingAlias(t *testing.T) {
	name := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	alias := &ast.AliasNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: name}
	anchor := &ast.AnchorNode{BaseNode: &ast.BaseNode{}, Start: dummyToken(), Value: alias}
	assert.True(t, rules.IsAliasNode(anchor))
}

func TestIsAliasNode_NonAlias(t *testing.T) {
	str := &ast.StringNode{BaseNode: &ast.BaseNode{}, Token: dummyToken()}
	assert.False(t, rules.IsAliasNode(str))

	mapping := &ast.MappingNode{BaseNode: &ast.BaseNode{}, Start: dummyToken()}
	assert.False(t, rules.IsAliasNode(mapping))

	assert.False(t, rules.IsAliasNode(nil))
}

// parseValueNode parses YAML and returns the value node for the given key.
func parseValueNode(t *testing.T, src, key string) ast.Node {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m := f.Docs[0].Body.(*ast.MappingNode)
	for _, kv := range m.Values {
		if kv.Key.GetToken().Value == key {
			return kv.Value
		}
	}
	t.Fatalf("key %q not found", key)
	return nil
}

func TestExpressionSpanToken_InlineString(t *testing.T) {
	node := parseValueNode(t, "run: echo ${{ github.actor }} done", "run")
	value := rules.StringValue(node)
	// value = "echo ${{ github.actor }} done"
	// ${{ starts at byte 5
	tok := rules.ExpressionSpanToken(node, value, 5, 24)
	assert.Equal(t, "${{ github.actor }}", tok.Value)
	assert.Equal(t, 1, tok.Position.Line)
	// "run: " occupies columns 1-5, value starts at col 6, + spanStart 5 = col 11
	assert.Equal(t, 11, tok.Position.Column)
}

func TestExpressionSpanToken_QuotedString(t *testing.T) {
	node := parseValueNode(t, `run: "echo ${{ github.actor }}"`, "run")
	value := rules.StringValue(node)
	tok := rules.ExpressionSpanToken(node, value, 5, 24)
	assert.Equal(t, "${{ github.actor }}", tok.Value)
	assert.Equal(t, 1, tok.Position.Line)
	// "run: " = col 1-5, quote at col 6, value starts col 7, + spanStart 5 = col 12
	assert.Equal(t, 12, tok.Position.Column)
}

func TestExpressionSpanToken_LiteralBlock_FirstLine(t *testing.T) {
	src := "run: |\n  echo ${{ github.actor }}\n  echo done\n"
	node := parseValueNode(t, src, "run")
	value := rules.StringValue(node)
	// value = "echo ${{ github.actor }}\necho done\n"
	// ${{ starts at byte 5
	tok := rules.ExpressionSpanToken(node, value, 5, 24)
	assert.Equal(t, "${{ github.actor }}", tok.Value)
	assert.Equal(t, 2, tok.Position.Line)   // | is line 1, first content line is 2
	assert.Equal(t, 8, tok.Position.Column) // indent(2) + 5 + 1 = 8
}

func TestExpressionSpanToken_LiteralBlock_SecondLine(t *testing.T) {
	src := "run: |\n  echo hello\n  echo ${{ github.token }}\n"
	node := parseValueNode(t, src, "run")
	value := rules.StringValue(node)
	// value = "echo hello\necho ${{ github.token }}\n"
	// "echo hello\n" = 11 bytes, then "echo " = 5 bytes, so ${{ at offset 16
	// ${{ github.token }} = 20 bytes, end at 36 but value has trailing \n
	tok := rules.ExpressionSpanToken(node, value, 16, 35)
	assert.Equal(t, "${{ github.token }}", tok.Value)
	assert.Equal(t, 3, tok.Position.Line)   // | line 1, first content line 2, second content line 3
	assert.Equal(t, 8, tok.Position.Column) // indent(2) + 5 + 1 = 8
}

func TestExpressionSpanToken_LiteralBlock_DeeperIndent(t *testing.T) {
	src := "run: |\n      echo ${{ github.actor }}\n"
	node := parseValueNode(t, src, "run")
	value := rules.StringValue(node)
	// value = "echo ${{ github.actor }}\n", indent = 6
	tok := rules.ExpressionSpanToken(node, value, 5, 24)
	assert.Equal(t, "${{ github.actor }}", tok.Value)
	assert.Equal(t, 2, tok.Position.Line)
	assert.Equal(t, 12, tok.Position.Column) // indent(6) + 5 + 1 = 12
}

func TestExpressionSpanTokens_NoExpressions(t *testing.T) {
	node := parseValueNode(t, "run: echo hello", "run")
	tokens := rules.ExpressionSpanTokens(node)
	assert.Nil(t, tokens)
}

func TestExpressionSpanTokens_MultipleSpans(t *testing.T) {
	node := parseValueNode(t, "run: echo ${{ a }} ${{ b }}", "run")
	tokens := rules.ExpressionSpanTokens(node)
	require.Len(t, tokens, 2)
	assert.Equal(t, "${{ a }}", tokens[0].Value)
	assert.Equal(t, "${{ b }}", tokens[1].Value)
}
