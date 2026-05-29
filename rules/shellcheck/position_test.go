package shellcheck

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// firstRunNode parses a workflow and returns the value node of the first step's
// run: key, plus its dedented string value.
func firstRunNode(t *testing.T, src string) (ast.Node, string) {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	wf := workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
	var node ast.Node
	wf.EachStep(func(step workflow.StepMapping) {
		if node != nil {
			return
		}
		if kv := step.FindKey("run"); kv != nil {
			node = kv.Value
		}
	})
	require.NotNil(t, node)
	return node, rules.StringValue(node)
}

func TestLineColToByteOffset(t *testing.T) {
	s := "echo $x\necho $y"
	assert.Equal(t, 0, lineColToByteOffset(s, 1, 1))
	assert.Equal(t, 5, lineColToByteOffset(s, 1, 6))  // '$' on line 1
	assert.Equal(t, 8, lineColToByteOffset(s, 2, 1))  // 'e' on line 2
	assert.Equal(t, 13, lineColToByteOffset(s, 2, 6)) // '$' on line 2
	// Column past end of line 1 clamps to the newline.
	assert.Equal(t, 7, lineColToByteOffset(s, 1, 99))
}

func TestSpanToken_LiteralBlockScalar(t *testing.T) {
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - run: |\n" +
		"          echo $x\n" +
		"          echo $y\n"
	node, value := firstRunNode(t, src)
	require.Equal(t, "echo $x\necho $y\n", value)

	// shellcheck would report $x at line 1, col 6 (endCol 8) within the script.
	tk := spanToken(node, value, value, 1, 6, 1, 8)
	assert.Equal(t, "$x", tk.Value)
	assert.Equal(t, 7, tk.Position.Line)    // YAML line of "echo $x"
	assert.Equal(t, 16, tk.Position.Column) // 10 indent + "echo " (5) + 1

	// $y on the second content line.
	tk2 := spanToken(node, value, value, 2, 6, 2, 8)
	assert.Equal(t, "$y", tk2.Value)
	assert.Equal(t, 8, tk2.Position.Line)
	assert.Equal(t, 16, tk2.Position.Column)
}

func TestSpanToken_InlinePlainScalar(t *testing.T) {
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - run: echo $x\n"
	node, value := firstRunNode(t, src)
	require.Equal(t, "echo $x", value)

	tk := spanToken(node, value, value, 1, 6, 1, 8)
	assert.Equal(t, "$x", tk.Value)
	assert.Equal(t, 6, tk.Position.Line) // run is on line 6
}
