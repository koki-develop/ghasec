package diagnostic

import "github.com/goccy/go-yaml/token"

type Error struct {
	Token       *token.Token
	BeforeToken *token.Token
	AfterToken  *token.Token
	RuleID      string
	Message     string
	// Markers holds additional tokens to highlight with MarkerDash (no text).
	Markers []*token.Token
}

func (e *Error) Error() string { return e.Message }
