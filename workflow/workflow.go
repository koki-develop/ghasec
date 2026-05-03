package workflow

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/git"
)

// Mapping wraps *ast.MappingNode with common navigation methods.
type Mapping struct{ *ast.MappingNode }

// FindKey searches for a key in the mapping and returns the corresponding
// MappingValueNode, or nil if not found.
func (m Mapping) FindKey(key string) *ast.MappingValueNode {
	if m.MappingNode == nil {
		return nil
	}
	for _, v := range m.Values {
		if v.Key.GetToken().Value == key {
			return v
		}
	}
	return nil
}

// FirstToken walks the token chain backward to the first non-comment token
// in the file. It returns a copy of that token with its Value trimmed to the
// first byte. Returns nil if the MappingNode is nil.
func (m Mapping) FirstToken() *token.Token {
	if m.MappingNode == nil {
		return nil
	}
	tk := m.GetToken()
	for tk.Prev != nil {
		tk = tk.Prev
	}
	// Skip leading comment tokens so file-level errors point to actual YAML content.
	for tk != nil && tk.Type == token.CommentType {
		tk = tk.Next
	}
	if tk == nil {
		tk = m.GetToken()
	}
	cp := *tk
	if len(tk.Value) > 0 {
		cp.Value = string(tk.Value[0])
	}
	return &cp
}

// WorkflowMapping represents the top-level workflow mapping.
type WorkflowMapping struct{ Mapping }

// ActionMapping represents the top-level action metadata mapping.
type ActionMapping struct{ Mapping }

// unwrapNode unwraps AnchorNode wrappers to get the actual value node.
// This is a local copy to avoid a circular import with the rules package.
func unwrapNode(n ast.Node) ast.Node {
	if n == nil {
		return nil
	}
	for {
		a, ok := n.(*ast.AnchorNode)
		if !ok {
			return n
		}
		n = a.Value
	}
}

// EachStep iterates over all steps in a composite action's runs.steps.
// It is a no-op for non-composite actions (where runs.steps does not exist).
// It silently skips malformed sections, consistent with WorkflowMapping.EachStep.
func (m ActionMapping) EachStep(fn func(step StepMapping)) {
	runsKV := m.FindKey("runs")
	if runsKV == nil {
		return
	}
	runsMapping, ok := unwrapNode(runsKV.Value).(*ast.MappingNode)
	if !ok {
		return
	}
	stepsKV := Mapping{runsMapping}.FindKey("steps")
	if stepsKV == nil {
		return
	}
	stepsSeq, ok := unwrapNode(stepsKV.Value).(*ast.SequenceNode)
	if !ok {
		return
	}
	for _, stepNode := range stepsSeq.Values {
		stepMapping, ok := unwrapNode(stepNode).(*ast.MappingNode)
		if !ok {
			continue
		}
		fn(StepMapping{Mapping: Mapping{stepMapping}})
	}
}

// EachJob iterates over all jobs in the workflow.
// It silently skips malformed sections (missing jobs key, non-mapping values, etc.)
// because structural validation is handled by the required invalid-workflow rule,
// which gates all non-required rules.
func (w WorkflowMapping) EachJob(fn func(jobKeyToken *token.Token, job JobMapping)) {
	jobsKV := w.FindKey("jobs")
	if jobsKV == nil {
		return
	}
	jobsMapping, ok := unwrapNode(jobsKV.Value).(*ast.MappingNode)
	if !ok {
		return
	}
	for _, jobEntry := range jobsMapping.Values {
		jobMapping, ok := unwrapNode(jobEntry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		fn(jobEntry.Key.GetToken(), JobMapping{Mapping{jobMapping}})
	}
}

// JobMapping represents a job-level mapping.
type JobMapping struct{ Mapping }

// Uses extracts the ActionRef from the job's "uses" key (used for reusable
// workflow references). Returns (ActionRef, false) if the job has no "uses"
// key or the value is not a string/literal node.
func (j JobMapping) Uses() (ActionRef, bool) {
	usesKV := j.FindKey("uses")
	if usesKV == nil {
		return ActionRef{}, false
	}
	switch v := unwrapNode(usesKV.Value).(type) {
	case *ast.StringNode:
		return NewActionRef(v.Value, v), true
	case *ast.LiteralNode:
		return NewActionRef(v.Value.Value, v), true
	}
	return ActionRef{}, false
}

// StepMapping represents a step-level mapping.
type StepMapping struct {
	Mapping
}

// EachStep iterates over all steps across all jobs in the workflow.
// It silently skips malformed sections (missing jobs, non-mapping jobs, etc.)
// because structural validation is handled by the required invalid-workflow rule,
// which gates all non-required rules.
func (w WorkflowMapping) EachStep(fn func(step StepMapping)) {
	w.EachJob(func(_ *token.Token, job JobMapping) {
		stepsKV := job.FindKey("steps")
		if stepsKV == nil {
			return
		}
		stepsSeq, ok := unwrapNode(stepsKV.Value).(*ast.SequenceNode)
		if !ok {
			return
		}
		for _, stepNode := range stepsSeq.Values {
			stepMapping, ok := unwrapNode(stepNode).(*ast.MappingNode)
			if !ok {
				continue
			}
			fn(StepMapping{Mapping: Mapping{stepMapping}})
		}
	})
}

// With returns the "with" mapping from the step.
// Returns (Mapping, false) if the step has no "with" key or the value
// is not a mapping node.
func (s StepMapping) With() (Mapping, bool) {
	withKV := s.FindKey("with")
	if withKV == nil {
		return Mapping{}, false
	}
	m, ok := unwrapNode(withKV.Value).(*ast.MappingNode)
	if !ok {
		return Mapping{}, false
	}
	return Mapping{m}, true
}

// Uses extracts the ActionRef from the step's "uses" key.
// Returns (ActionRef, false) if the step has no "uses" key or the value
// is not a string/literal node.
func (s StepMapping) Uses() (ActionRef, bool) {
	usesKV := s.FindKey("uses")
	if usesKV == nil {
		return ActionRef{}, false
	}
	switch v := unwrapNode(usesKV.Value).(type) {
	case *ast.StringNode:
		return NewActionRef(v.Value, v), true
	case *ast.LiteralNode:
		return NewActionRef(v.Value.Value, v), true
	}
	return ActionRef{}, false
}

// ActionRef holds a step's "uses" value together with its source AST node.
// The node is either a *ast.StringNode (plain or quoted scalar) or a
// *ast.LiteralNode (block scalar). RefToken dispatches on the node type so
// the caret position is correct regardless of which scalar form was used.
type ActionRef struct {
	value string
	node  ast.Node
}

// NewActionRef creates a new ActionRef. node is the AST node of the "uses"
// value (typically *ast.StringNode or *ast.LiteralNode); it may be nil in
// tests that do not need positional information.
func NewActionRef(value string, node ast.Node) ActionRef {
	return ActionRef{value: value, node: node}
}

// String returns the raw uses value (e.g. "actions/checkout@abc123").
func (a ActionRef) String() string { return a.value }

// Token returns the source token for error reporting. Returns nil if the
// ActionRef was constructed without an AST node.
func (a ActionRef) Token() *token.Token {
	if a.node == nil {
		return nil
	}
	return a.node.GetToken()
}

// RefToken returns a token pointing to just the ref portion (after "@").
// If there is no "@", it returns the full token. For literal block scalars,
// the line and column are computed across the indicator/content boundary so
// the caret lands on the actual ref characters in the source.
func (a ActionRef) RefToken() *token.Token {
	tk := a.Token()
	if tk == nil || tk.Position == nil {
		return tk
	}
	idx := strings.LastIndex(a.value, "@")
	if idx == -1 {
		return tk
	}
	ref := a.value[idx+1:]
	skip := idx + 1

	if lit, ok := a.node.(*ast.LiteralNode); ok {
		return literalRefToken(lit, a.value, skip, ref)
	}

	quoteOffset := 0
	if tk.Type == token.DoubleQuoteType || tk.Type == token.SingleQuoteType {
		quoteOffset = 1
	}
	cp := *tk
	cp.Type = token.StringType
	cp.Value = ref
	cp.Position = &token.Position{
		Line:   tk.Position.Line,
		Column: tk.Position.Column + quoteOffset + skip,
		Offset: tk.Position.Offset + quoteOffset + skip,
	}
	return &cp
}

// literalRefToken computes a synthetic token at byte offset spanStart within
// a literal block scalar's value, mapping it back to a source (line, column)
// by counting newlines in the value and applying the block's content
// indentation. The block indicator (|, |-, >) sits on its own line, so the
// content's first source line is indicator_line + 1.
func literalRefToken(lit *ast.LiteralNode, value string, spanStart int, refValue string) *token.Token {
	base := lit.Start

	indent := 0
	if lit.Value != nil {
		valTok := lit.Value.GetToken()
		if valTok != nil && valTok.Origin != "" && value != "" {
			originFirst := strings.SplitN(valTok.Origin, "\n", 2)[0]
			valueFirst := strings.SplitN(value, "\n", 2)[0]
			if d := len(originFirst) - len(valueFirst); d > 0 {
				indent = d
			}
		}
	}

	prefix := value[:spanStart]
	lineOffset := strings.Count(prefix, "\n")
	lastNL := strings.LastIndex(prefix, "\n")
	col := indent + (spanStart - lastNL - 1) + 1
	line := base.Position.Line + 1 + lineOffset

	return &token.Token{
		Type:  token.StringType,
		Value: refValue,
		Prev:  base.Prev,
		Position: &token.Position{
			Line:   line,
			Column: col,
			Offset: base.Position.Offset + spanStart,
		},
	}
}

// IsLocal reports whether the action is a local path reference (starts with "./").
func (a ActionRef) IsLocal() bool { return strings.HasPrefix(a.value, "./") }

// IsDocker reports whether the action is a Docker reference (starts with "docker://").
func (a ActionRef) IsDocker() bool { return strings.HasPrefix(a.value, "docker://") }

// Ref returns the git reference portion after the last "@".
// Returns an empty Ref if there is no "@".
func (a ActionRef) Ref() git.Ref {
	idx := strings.LastIndex(a.value, "@")
	if idx == -1 {
		return ""
	}
	return git.Ref(a.value[idx+1:])
}

// OwnerRepo extracts the owner and repo from the action path (before "@").
// Returns empty strings for local actions, Docker actions, or paths that
// do not contain at least owner/repo.
func (a ActionRef) OwnerRepo() (string, string) {
	if a.IsLocal() || a.IsDocker() {
		return "", ""
	}
	v := a.value
	if idx := strings.LastIndex(v, "@"); idx != -1 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, "/", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// SubPath returns the subdirectory path within the repo for actions that use
// the owner/repo/path@ref format (e.g., "actions/aws/ec2@v1" returns "ec2").
// Returns an empty string if there is no subdirectory component.
func (a ActionRef) SubPath() string {
	if a.IsLocal() || a.IsDocker() {
		return ""
	}
	v := a.value
	if idx := strings.LastIndex(v, "@"); idx != -1 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, "/", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}
