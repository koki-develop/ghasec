package expression

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

type lexer struct {
	input  string
	pos    int
	errors []Error
}

func newLexer(input string) *lexer {
	return &lexer{input: input}
}

func (l *lexer) next() Token {
	for {
		l.skipWhitespace()
		if l.pos >= len(l.input) {
			return Token{Kind: TokenEOF, Offset: l.pos}
		}

		start := l.pos
		ch, size := utf8.DecodeRuneInString(l.input[l.pos:])

		if ch == '\'' {
			return l.scanString()
		}
		if ch >= '0' && ch <= '9' {
			return l.scanNumber()
		}
		if ch == '_' || unicode.IsLetter(ch) {
			return l.scanIdent()
		}

		l.pos += size
		switch ch {
		case '(':
			return Token{Kind: TokenLParen, Value: "(", Offset: start}
		case ')':
			return Token{Kind: TokenRParen, Value: ")", Offset: start}
		case '[':
			return Token{Kind: TokenLBracket, Value: "[", Offset: start}
		case ']':
			return Token{Kind: TokenRBracket, Value: "]", Offset: start}
		case '.':
			return Token{Kind: TokenDot, Value: ".", Offset: start}
		case '*':
			return Token{Kind: TokenStar, Value: "*", Offset: start}
		case ',':
			return Token{Kind: TokenComma, Value: ",", Offset: start}
		case '!':
			if l.peek() == '=' {
				l.pos++
				return Token{Kind: TokenNE, Value: "!=", Offset: start}
			}
			return Token{Kind: TokenNot, Value: "!", Offset: start}
		case '<':
			if l.peek() == '=' {
				l.pos++
				return Token{Kind: TokenLE, Value: "<=", Offset: start}
			}
			return Token{Kind: TokenLT, Value: "<", Offset: start}
		case '>':
			if l.peek() == '=' {
				l.pos++
				return Token{Kind: TokenGE, Value: ">=", Offset: start}
			}
			return Token{Kind: TokenGT, Value: ">", Offset: start}
		case '=':
			if l.peek() == '=' {
				l.pos++
				return Token{Kind: TokenEQ, Value: "==", Offset: start}
			}
			l.addError(start, "unexpected character '='")
			continue
		case '&':
			if l.peek() == '&' {
				l.pos++
				return Token{Kind: TokenAnd, Value: "&&", Offset: start}
			}
			l.addError(start, "unexpected character '&'")
			continue
		case '|':
			if l.peek() == '|' {
				l.pos++
				return Token{Kind: TokenOr, Value: "||", Offset: start}
			}
			l.addError(start, "unexpected character '|'")
			continue
		default:
			l.addError(start, fmt.Sprintf("unexpected character %q", string(ch)))
			continue
		}
	}
}

func (l *lexer) peek() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			l.pos++
		} else {
			break
		}
	}
}

func (l *lexer) scanString() Token {
	start := l.pos
	l.pos++ // skip opening quote
	var value []byte
	for {
		if l.pos >= len(l.input) {
			l.addError(start, "unterminated string literal")
			return Token{Kind: TokenString, Value: string(value), Offset: start}
		}
		ch := l.input[l.pos]
		if ch == '\'' {
			l.pos++
			if l.pos < len(l.input) && l.input[l.pos] == '\'' {
				value = append(value, '\'')
				l.pos++
				continue
			}
			return Token{Kind: TokenString, Value: string(value), Offset: start}
		}
		value = append(value, ch)
		l.pos++
	}
}

func (l *lexer) scanNumber() Token {
	start := l.pos
	if l.input[l.pos] == '0' && l.pos+1 < len(l.input) && (l.input[l.pos+1] == 'x' || l.input[l.pos+1] == 'X') {
		l.pos += 2
		for l.pos < len(l.input) && isHexDigit(l.input[l.pos]) {
			l.pos++
		}
		if l.pos == start+2 {
			l.addError(start, "invalid hex literal: expected digits after '0x'")
		}
		return Token{Kind: TokenInt, Value: l.input[start:l.pos], Offset: start}
	}
	l.scanDigits()
	isFloat := false
	if l.pos < len(l.input) && l.input[l.pos] == '.' {
		if l.pos+1 < len(l.input) && l.input[l.pos+1] >= '0' && l.input[l.pos+1] <= '9' {
			isFloat = true
			l.pos++
			l.scanDigits()
		}
	}
	if l.pos < len(l.input) && (l.input[l.pos] == 'e' || l.input[l.pos] == 'E') {
		isFloat = true
		l.pos++
		if l.pos < len(l.input) && (l.input[l.pos] == '+' || l.input[l.pos] == '-') {
			l.pos++
		}
		before := l.pos
		l.scanDigits()
		if l.pos == before {
			l.addError(start, "invalid number: expected digits after exponent")
		}
	}
	value := l.input[start:l.pos]
	if isFloat {
		return Token{Kind: TokenFloat, Value: value, Offset: start}
	}
	return Token{Kind: TokenInt, Value: value, Offset: start}
}

func (l *lexer) scanDigits() {
	for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
		l.pos++
	}
}

func (l *lexer) scanIdent() Token {
	start := l.pos
	for l.pos < len(l.input) {
		ch, size := utf8.DecodeRuneInString(l.input[l.pos:])
		if ch == '_' || ch == '-' || unicode.IsLetter(ch) || unicode.IsDigit(ch) {
			l.pos += size
		} else {
			break
		}
	}
	value := l.input[start:l.pos]
	switch value {
	case "true":
		return Token{Kind: TokenTrue, Value: value, Offset: start}
	case "false":
		return Token{Kind: TokenFalse, Value: value, Offset: start}
	case "null":
		return Token{Kind: TokenNull, Value: value, Offset: start}
	default:
		return Token{Kind: TokenIdent, Value: value, Offset: start}
	}
}

func (l *lexer) addError(offset int, message string) {
	l.errors = append(l.errors, Error{Offset: offset, Message: message})
}

func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}
