package main

// Node represents a schema constraint extracted from JSON Schema.
type Node struct {
	Path                  string
	Types                 []string
	Properties            map[string]*Node
	Required              []string
	Enum                  []string
	PatternProps          map[string]*Node
	AdditionalProperties  *bool
	AdditionalPropsSchema *Node // schema constraint for additionalProperties values (G1)
	Items                 *Node
	OneOf                 []*Node
	AllOf                 []*Node
	AnyOf                 []*Node
	If                    *Node
	Then                  *Node
	Else                  *Node
	Const                 *string
	RefName               string
	ParentName            string
	ContextTerm           string
	SkipChildren          bool
	MinItems              int                 // minimum number of sequence items (G4)
	MinProperties         int                 // minimum number of mapping properties (G4)
	Pattern               string              // string regex pattern constraint (G5)
	Dependencies          map[string][]string // property dependencies: key → required co-keys (V3)
}
