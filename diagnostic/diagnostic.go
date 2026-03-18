package diagnostic

import "github.com/goccy/go-yaml/token"

type Error struct {
	Token        *token.Token
	ContextToken *token.Token
	RuleID       string
	Message      string
}

func (e *Error) Error() string { return e.Message }
