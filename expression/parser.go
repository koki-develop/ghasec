package expression

import "fmt"

type parser struct {
	lexer  *lexer
	cur    Token
	errors []Error
}

func newParser(input string) *parser {
	l := newLexer(input)
	p := &parser{lexer: l}
	p.advance()
	return p
}

func (p *parser) advance() {
	p.cur = p.lexer.next()
}

func (p *parser) addError(msg string) {
	p.errors = append(p.errors, Error{Offset: p.cur.Offset, Message: msg})
}

func (p *parser) parse() []Error {
	if p.cur.Kind == TokenEOF && len(p.lexer.errors) > 0 {
		return p.lexer.errors
	}
	if p.cur.Kind == TokenEOF {
		p.addError("expected expression, but got end of input")
		return append(p.lexer.errors, p.errors...)
	}
	p.parseExpression()
	if p.cur.Kind != TokenEOF {
		p.addError(fmt.Sprintf("unexpected token %s after expression", p.tokenDesc()))
	}
	return append(p.lexer.errors, p.errors...)
}

func (p *parser) tokenDesc() string {
	if p.cur.Kind == TokenEOF {
		return "end of input"
	}
	if p.cur.Kind == TokenIdent || p.cur.Kind == TokenInt || p.cur.Kind == TokenFloat {
		return fmt.Sprintf("'%s'", p.cur.Value)
	}
	if p.cur.Kind == TokenString {
		return fmt.Sprintf("'%s'", p.cur.Value)
	}
	return p.cur.Kind.String()
}

func (p *parser) parseExpression() { p.parseOr() }

func (p *parser) parseOr() {
	p.parseAnd()
	for p.cur.Kind == TokenOr {
		p.advance()
		if !p.expectExpression("'||'") {
			return
		}
		p.parseAnd()
	}
}

func (p *parser) parseAnd() {
	p.parseEquality()
	for p.cur.Kind == TokenAnd {
		p.advance()
		if !p.expectExpression("'&&'") {
			return
		}
		p.parseEquality()
	}
}

func (p *parser) parseEquality() {
	p.parseComparison()
	for p.cur.Kind == TokenEQ || p.cur.Kind == TokenNE {
		op := p.cur.Kind.String()
		p.advance()
		if !p.expectExpression(op) {
			return
		}
		p.parseComparison()
	}
}

func (p *parser) parseComparison() {
	p.parseNot()
	for p.cur.Kind == TokenLT || p.cur.Kind == TokenLE || p.cur.Kind == TokenGT || p.cur.Kind == TokenGE {
		op := p.cur.Kind.String()
		p.advance()
		if !p.expectExpression(op) {
			return
		}
		p.parseNot()
	}
}

func (p *parser) parseNot() {
	if p.cur.Kind == TokenNot {
		p.advance()
		if !p.expectExpression("'!'") {
			return
		}
		p.parseNot()
		return
	}
	p.parsePrimary()
}

func (p *parser) parsePrimary() {
	switch p.cur.Kind {
	case TokenString, TokenInt, TokenFloat, TokenTrue, TokenFalse, TokenNull:
		p.advance()
	case TokenIdent:
		p.advance()
		if p.cur.Kind == TokenLParen {
			p.parseFunctionArgs()
			p.parsePostfix()
		} else {
			p.parsePostfix()
		}
	case TokenLParen:
		p.advance()
		if p.cur.Kind == TokenEOF {
			p.addError("expected expression after '('")
			return
		}
		p.parseExpression()
		if p.cur.Kind != TokenRParen {
			p.addError(fmt.Sprintf("expected ')', but got %s", p.eofOr()))
			return
		}
		p.advance()
		p.parsePostfix()
	default:
		p.addError(fmt.Sprintf("expected expression, but got %s", p.tokenDesc()))
		p.advance() // consume the bad token to avoid duplicate errors from callers
	}
}

func (p *parser) parsePostfix() {
	for {
		switch p.cur.Kind {
		case TokenDot:
			p.advance()
			switch p.cur.Kind {
			case TokenStar:
				p.advance()
			case TokenIdent:
				p.advance()
			default:
				p.addError("expected property name after '.'")
				return
			}
		case TokenLBracket:
			p.advance()
			if p.cur.Kind == TokenEOF {
				p.addError("expected expression after '['")
				return
			}
			p.parseExpression()
			if p.cur.Kind != TokenRBracket {
				p.addError(fmt.Sprintf("expected ']', but got %s", p.eofOr()))
				return
			}
			p.advance()
		default:
			return
		}
	}
}

func (p *parser) parseFunctionArgs() {
	p.advance() // skip (
	if p.cur.Kind == TokenRParen {
		p.advance()
		return
	}
	if p.cur.Kind == TokenEOF {
		p.addError("expected expression or ')' in function call, but got end of input")
		return
	}
	p.parseExpression()
	for p.cur.Kind == TokenComma {
		p.advance()
		if p.cur.Kind == TokenEOF {
			p.addError("expected expression after ',' in function call, but got end of input")
			return
		}
		p.parseExpression()
	}
	if p.cur.Kind != TokenRParen {
		p.addError(fmt.Sprintf("expected ')' after function arguments, but got %s", p.eofOr()))
		return
	}
	p.advance()
}

func (p *parser) expectExpression(after string) bool {
	if p.cur.Kind == TokenEOF {
		p.addError(fmt.Sprintf("expected expression after %s", after))
		return false
	}
	if !p.isExpressionStart() {
		p.addError(fmt.Sprintf("expected expression after %s, but got %s", after, p.tokenDesc()))
		p.advance() // consume bad token to prevent duplicate error in parse()
		return false
	}
	return true
}

func (p *parser) isExpressionStart() bool {
	switch p.cur.Kind {
	case TokenIdent, TokenInt, TokenFloat, TokenString,
		TokenTrue, TokenFalse, TokenNull,
		TokenLParen, TokenNot:
		return true
	}
	return false
}

func (p *parser) eofOr() string {
	if p.cur.Kind == TokenEOF {
		return "end of input"
	}
	return p.tokenDesc()
}
