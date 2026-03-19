package diagnostic

import "github.com/goccy/go-yaml/token"

type Error struct {
	Token   *token.Token
	RuleID  string
	Message string
	// ContextTokens holds tokens to display as context (MarkerNone, no text).
	// Rendered in file-position order.
	ContextTokens []*token.Token
	// Markers holds additional tokens to highlight with MarkerCaret (no text).
	Markers []*token.Token
}

func (e *Error) Error() string { return e.Message }
