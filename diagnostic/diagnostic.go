package diagnostic

import "github.com/goccy/go-yaml/token"

type Error struct {
	Token   *token.Token
	RuleID  string
	Message string
	// ExtraContexts holds non-ancestor tokens to display as additional context
	// (MarkerNone, no text). Ancestor breadcrumbs are computed automatically
	// by the renderer from the Token's position.
	ExtraContexts []*token.Token
	// Markers holds additional tokens to highlight with MarkerCaret (no text).
	Markers []*token.Token
}

func (e *Error) Error() string { return e.Message }
