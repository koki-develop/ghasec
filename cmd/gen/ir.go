package main

// Node represents a schema constraint extracted from JSON Schema.
type Node struct {
	Path                 string
	Types                []string
	Properties           map[string]*Node
	Required             []string
	Enum                 []string
	PatternProps         map[string]*Node
	AdditionalProperties *bool
	Items                *Node
	OneOf                []*Node
	AllOf                []*Node
	AnyOf                []*Node
	If                   *Node
	Then                 *Node
	Else                 *Node
	Const                *string
	RefName              string
	ParentName           string
	ContextTerm          string
	SkipChildren         bool
}
