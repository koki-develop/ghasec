package diagnostic

import "github.com/goccy/go-yaml/token"

type Error struct {
	Token   *token.Token
	Message string
}

func (e *Error) Error() string { return e.Message }
