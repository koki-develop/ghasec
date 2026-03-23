package expression

import "fmt"

type TokenKind int

const (
	TokenEOF TokenKind = iota
	TokenIdent
	TokenInt
	TokenFloat
	TokenString
	TokenTrue
	TokenFalse
	TokenNull
	TokenLParen
	TokenRParen
	TokenLBracket
	TokenRBracket
	TokenDot
	TokenStar
	TokenNot
	TokenLT
	TokenLE
	TokenGT
	TokenGE
	TokenEQ
	TokenNE
	TokenAnd
	TokenOr
	TokenComma
)

func (k TokenKind) String() string {
	switch k {
	case TokenEOF:
		return "end of input"
	case TokenIdent:
		return "identifier"
	case TokenInt:
		return "integer"
	case TokenFloat:
		return "float"
	case TokenString:
		return "string"
	case TokenTrue:
		return "'true'"
	case TokenFalse:
		return "'false'"
	case TokenNull:
		return "'null'"
	case TokenLParen:
		return "'('"
	case TokenRParen:
		return "')'"
	case TokenLBracket:
		return "'['"
	case TokenRBracket:
		return "']'"
	case TokenDot:
		return "'.'"
	case TokenStar:
		return "'*'"
	case TokenNot:
		return "'!'"
	case TokenLT:
		return "'<'"
	case TokenLE:
		return "'<='"
	case TokenGT:
		return "'>'"
	case TokenGE:
		return "'>='"
	case TokenEQ:
		return "'=='"
	case TokenNE:
		return "'!='"
	case TokenAnd:
		return "'&&'"
	case TokenOr:
		return "'||'"
	case TokenComma:
		return "','"
	default:
		return fmt.Sprintf("TokenKind(%d)", k)
	}
}

type Token struct {
	Kind   TokenKind
	Value  string
	Offset int
}
