package expression

// Walk traverses the AST in pre-order. fn is called for each node.
// If fn returns false, the children of that node are not visited.
func Walk(node Node, fn func(Node) bool) {
	if node == nil {
		return
	}
	if !fn(node) {
		return
	}
	switch n := node.(type) {
	case *BinaryNode:
		Walk(n.Left, fn)
		Walk(n.Right, fn)
	case *UnaryNode:
		Walk(n.Operand, fn)
	case *PropertyAccessNode:
		Walk(n.Object, fn)
	case *IndexAccessNode:
		Walk(n.Object, fn)
		Walk(n.Index, fn)
	case *FilterNode:
		Walk(n.Object, fn)
	case *FunctionCallNode:
		for _, arg := range n.Args {
			Walk(arg, fn)
		}
	case *ParenNode:
		Walk(n.Inner, fn)
	case *IdentNode, *LiteralNode:
		// leaf nodes
	}
}
