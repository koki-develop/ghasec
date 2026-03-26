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

func (p *parser) parse() (Node, []Error) {
	if p.cur.Kind == TokenEOF && len(p.lexer.errors) > 0 {
		return nil, p.lexer.errors
	}
	if p.cur.Kind == TokenEOF {
		p.addError("expected expression, but got end of input")
		return nil, append(p.lexer.errors, p.errors...)
	}
	node := p.parseExpression()
	if p.cur.Kind != TokenEOF {
		p.addError(fmt.Sprintf("unexpected token %s after expression", p.tokenDesc()))
	}
	errs := append(p.lexer.errors, p.errors...)
	if len(errs) > 0 {
		return nil, errs
	}
	return node, nil
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

func (p *parser) parseExpression() Node { return p.parseOr() }

func (p *parser) parseOr() Node {
	left := p.parseAnd()
	for p.cur.Kind == TokenOr {
		offset := p.cur.Offset
		p.advance()
		if !p.expectExpression("'||'") {
			return nil
		}
		right := p.parseAnd()
		left = &BinaryNode{Op: TokenOr, Left: left, Right: right, Offset: offset}
	}
	return left
}

func (p *parser) parseAnd() Node {
	left := p.parseEquality()
	for p.cur.Kind == TokenAnd {
		offset := p.cur.Offset
		p.advance()
		if !p.expectExpression("'&&'") {
			return nil
		}
		right := p.parseEquality()
		left = &BinaryNode{Op: TokenAnd, Left: left, Right: right, Offset: offset}
	}
	return left
}

func (p *parser) parseEquality() Node {
	left := p.parseComparison()
	for p.cur.Kind == TokenEQ || p.cur.Kind == TokenNE {
		op := p.cur.Kind
		offset := p.cur.Offset
		p.advance()
		if !p.expectExpression(op.String()) {
			return nil
		}
		right := p.parseComparison()
		left = &BinaryNode{Op: op, Left: left, Right: right, Offset: offset}
	}
	return left
}

func (p *parser) parseComparison() Node {
	left := p.parseNot()
	for p.cur.Kind == TokenLT || p.cur.Kind == TokenLE || p.cur.Kind == TokenGT || p.cur.Kind == TokenGE {
		op := p.cur.Kind
		offset := p.cur.Offset
		p.advance()
		if !p.expectExpression(op.String()) {
			return nil
		}
		right := p.parseNot()
		left = &BinaryNode{Op: op, Left: left, Right: right, Offset: offset}
	}
	return left
}

func (p *parser) parseNot() Node {
	if p.cur.Kind == TokenNot {
		offset := p.cur.Offset
		p.advance()
		if !p.expectExpression("'!'") {
			return nil
		}
		operand := p.parseNot()
		return &UnaryNode{Op: TokenNot, Operand: operand, Offset: offset}
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() Node {
	switch p.cur.Kind {
	case TokenString, TokenInt, TokenFloat, TokenTrue, TokenFalse, TokenNull:
		node := &LiteralNode{Kind: p.cur.Kind, Value: p.cur.Value, Offset: p.cur.Offset}
		p.advance()
		return node
	case TokenIdent:
		name := p.cur.Value
		offset := p.cur.Offset
		p.advance()
		if p.cur.Kind == TokenLParen {
			node := p.parseFunctionArgs(name, offset)
			return p.parsePostfix(node)
		}
		node := &IdentNode{Name: name, Offset: offset}
		return p.parsePostfix(node)
	case TokenLParen:
		offset := p.cur.Offset
		p.advance()
		if p.cur.Kind == TokenEOF {
			p.addError("expected expression after '('")
			return nil
		}
		inner := p.parseExpression()
		if p.cur.Kind != TokenRParen {
			p.addError(fmt.Sprintf("expected ')', but got %s", p.eofOr()))
			return nil
		}
		p.advance()
		node := &ParenNode{Inner: inner, Offset: offset}
		return p.parsePostfix(node)
	default:
		p.addError(fmt.Sprintf("expected expression, but got %s", p.tokenDesc()))
		p.advance() // consume the bad token to avoid duplicate errors from callers
		return nil
	}
}

func (p *parser) parsePostfix(node Node) Node {
	for {
		switch p.cur.Kind {
		case TokenDot:
			p.advance()
			switch p.cur.Kind {
			case TokenStar:
				p.advance()
				node = &FilterNode{Object: node, Offset: node.NodeOffset()}
			case TokenIdent:
				prop := p.cur.Value
				p.advance()
				node = &PropertyAccessNode{Object: node, Property: prop, Offset: node.NodeOffset()}
			default:
				p.addError("expected property name after '.'")
				return node
			}
		case TokenLBracket:
			p.advance()
			if p.cur.Kind == TokenEOF {
				p.addError("expected expression after '['")
				return node
			}
			index := p.parseExpression()
			if p.cur.Kind != TokenRBracket {
				p.addError(fmt.Sprintf("expected ']', but got %s", p.eofOr()))
				return node
			}
			p.advance()
			node = &IndexAccessNode{Object: node, Index: index, Offset: node.NodeOffset()}
		default:
			return node
		}
	}
}

func (p *parser) parseFunctionArgs(name string, offset int) Node {
	p.advance() // skip (
	var args []Node
	if p.cur.Kind == TokenRParen {
		p.advance()
		return &FunctionCallNode{Name: name, Args: args, Offset: offset}
	}
	if p.cur.Kind == TokenEOF {
		p.addError("expected expression or ')' in function call, but got end of input")
		return &FunctionCallNode{Name: name, Args: args, Offset: offset}
	}
	args = append(args, p.parseExpression())
	for p.cur.Kind == TokenComma {
		p.advance()
		if p.cur.Kind == TokenEOF {
			p.addError("expected expression after ',' in function call, but got end of input")
			return &FunctionCallNode{Name: name, Args: args, Offset: offset}
		}
		args = append(args, p.parseExpression())
	}
	if p.cur.Kind != TokenRParen {
		p.addError(fmt.Sprintf("expected ')' after function arguments, but got %s", p.eofOr()))
		return &FunctionCallNode{Name: name, Args: args, Offset: offset}
	}
	p.advance()
	return &FunctionCallNode{Name: name, Args: args, Offset: offset}
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
