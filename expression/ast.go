package expression

// Node is the interface for all expression AST nodes.
// Every node carries an offset (byte position within the expression string).
type Node interface {
	nodeMarker()
	NodeOffset() int
}

// BinaryNode represents a binary operation (==, !=, &&, ||, <, <=, >, >=).
type BinaryNode struct {
	Op     TokenKind
	Left   Node
	Right  Node
	Offset int
}

func (*BinaryNode) nodeMarker()       {}
func (n *BinaryNode) NodeOffset() int { return n.Offset }

// UnaryNode represents the unary ! operator.
type UnaryNode struct {
	Op      TokenKind
	Operand Node
	Offset  int
}

func (*UnaryNode) nodeMarker()       {}
func (n *UnaryNode) NodeOffset() int { return n.Offset }

// IdentNode represents a bare identifier (e.g., "github", "matrix").
type IdentNode struct {
	Name   string
	Offset int
}

func (*IdentNode) nodeMarker()       {}
func (n *IdentNode) NodeOffset() int { return n.Offset }

// PropertyAccessNode represents dot access (e.g., github.actor).
type PropertyAccessNode struct {
	Object   Node
	Property string
	Offset   int
}

func (*PropertyAccessNode) nodeMarker()       {}
func (n *PropertyAccessNode) NodeOffset() int { return n.Offset }

// IndexAccessNode represents bracket access (e.g., matrix['os']).
type IndexAccessNode struct {
	Object Node
	Index  Node
	Offset int
}

func (*IndexAccessNode) nodeMarker()       {}
func (n *IndexAccessNode) NodeOffset() int { return n.Offset }

// FilterNode represents a wildcard filter (e.g., steps.*.outcome).
type FilterNode struct {
	Object Node
	Offset int
}

func (*FilterNode) nodeMarker()       {}
func (n *FilterNode) NodeOffset() int { return n.Offset }

// LiteralNode represents a literal value (string, int, float, true, false, null).
type LiteralNode struct {
	Kind   TokenKind
	Value  string
	Offset int
}

func (*LiteralNode) nodeMarker()       {}
func (n *LiteralNode) NodeOffset() int { return n.Offset }

// FunctionCallNode represents a function call (e.g., contains(a, b)).
type FunctionCallNode struct {
	Name   string
	Args   []Node
	Offset int
}

func (*FunctionCallNode) nodeMarker()       {}
func (n *FunctionCallNode) NodeOffset() int { return n.Offset }

// ParenNode represents a parenthesized expression.
type ParenNode struct {
	Inner  Node
	Offset int
}

func (*ParenNode) nodeMarker()       {}
func (n *ParenNode) NodeOffset() int { return n.Offset }
