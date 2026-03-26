package expression

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWalk(t *testing.T) {
	// github.actor == 'dependabot[bot]'
	tree := &BinaryNode{
		Op: TokenEQ,
		Left: &PropertyAccessNode{
			Object:   &IdentNode{Name: "github", Offset: 0},
			Property: "actor",
			Offset:   0,
		},
		Right:  &LiteralNode{Kind: TokenString, Value: "dependabot[bot]", Offset: 18},
		Offset: 0,
	}

	var visited []string
	Walk(tree, func(n Node) bool {
		switch v := n.(type) {
		case *BinaryNode:
			visited = append(visited, "binary:"+v.Op.String())
		case *PropertyAccessNode:
			visited = append(visited, "prop:"+v.Property)
		case *IdentNode:
			visited = append(visited, "ident:"+v.Name)
		case *LiteralNode:
			visited = append(visited, "literal:"+v.Value)
		}
		return true
	})

	assert.Equal(t, []string{
		"binary:'=='",
		"prop:actor",
		"ident:github",
		"literal:dependabot[bot]",
	}, visited)
}

func TestWalk_SkipChildren(t *testing.T) {
	tree := &BinaryNode{
		Op: TokenAnd,
		Left: &BinaryNode{
			Op:     TokenEQ,
			Left:   &IdentNode{Name: "a", Offset: 0},
			Right:  &IdentNode{Name: "b", Offset: 5},
			Offset: 0,
		},
		Right:  &IdentNode{Name: "c", Offset: 10},
		Offset: 0,
	}

	var visited []string
	Walk(tree, func(n Node) bool {
		switch v := n.(type) {
		case *BinaryNode:
			visited = append(visited, "binary:"+v.Op.String())
			return v.Op != TokenEQ
		case *IdentNode:
			visited = append(visited, "ident:"+v.Name)
		}
		return true
	})

	assert.Equal(t, []string{
		"binary:'&&'",
		"binary:'=='",
		"ident:c",
	}, visited)
}

func TestWalk_NilNode(t *testing.T) {
	Walk(nil, func(n Node) bool { return true })
}

func TestWalk_AllNodeTypes(t *testing.T) {
	tree := &UnaryNode{
		Op: TokenNot,
		Operand: &ParenNode{
			Inner: &BinaryNode{
				Op: TokenAnd,
				Left: &FunctionCallNode{
					Name: "contains",
					Args: []Node{
						&FilterNode{
							Object: &IdentNode{Name: "steps", Offset: 0},
							Offset: 0,
						},
					},
					Offset: 0,
				},
				Right: &IndexAccessNode{
					Object: &IdentNode{Name: "matrix", Offset: 0},
					Index:  &LiteralNode{Kind: TokenString, Value: "os", Offset: 0},
					Offset: 0,
				},
				Offset: 0,
			},
			Offset: 0,
		},
		Offset: 0,
	}

	var types []string
	Walk(tree, func(n Node) bool {
		switch n.(type) {
		case *UnaryNode:
			types = append(types, "unary")
		case *ParenNode:
			types = append(types, "paren")
		case *BinaryNode:
			types = append(types, "binary")
		case *FunctionCallNode:
			types = append(types, "func")
		case *FilterNode:
			types = append(types, "filter")
		case *IdentNode:
			types = append(types, "ident")
		case *IndexAccessNode:
			types = append(types, "index")
		case *LiteralNode:
			types = append(types, "literal")
		}
		return true
	})

	assert.Equal(t, []string{
		"unary", "paren", "binary",
		"func", "filter", "ident",
		"index", "ident", "literal",
	}, types)
}
