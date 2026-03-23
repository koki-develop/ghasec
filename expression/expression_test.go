package expression

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collectTokens(input string) []Token {
	l := newLexer(input)
	var tokens []Token
	for {
		tok := l.next()
		tokens = append(tokens, tok)
		if tok.Kind == TokenEOF {
			break
		}
	}
	return tokens
}

func TestLexer(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []Token
	}{
		{
			name:  "single char punctuation",
			input: "( ) [ ] . * ! , < >",
			expect: []Token{
				{Kind: TokenLParen, Value: "(", Offset: 0},
				{Kind: TokenRParen, Value: ")", Offset: 2},
				{Kind: TokenLBracket, Value: "[", Offset: 4},
				{Kind: TokenRBracket, Value: "]", Offset: 6},
				{Kind: TokenDot, Value: ".", Offset: 8},
				{Kind: TokenStar, Value: "*", Offset: 10},
				{Kind: TokenNot, Value: "!", Offset: 12},
				{Kind: TokenComma, Value: ",", Offset: 14},
				{Kind: TokenLT, Value: "<", Offset: 16},
				{Kind: TokenGT, Value: ">", Offset: 18},
				{Kind: TokenEOF, Offset: 19},
			},
		},
		{
			name:  "multi char operators",
			input: "<= >= == != && ||",
			expect: []Token{
				{Kind: TokenLE, Value: "<=", Offset: 0},
				{Kind: TokenGE, Value: ">=", Offset: 3},
				{Kind: TokenEQ, Value: "==", Offset: 6},
				{Kind: TokenNE, Value: "!=", Offset: 9},
				{Kind: TokenAnd, Value: "&&", Offset: 12},
				{Kind: TokenOr, Value: "||", Offset: 15},
				{Kind: TokenEOF, Offset: 17},
			},
		},
		{
			name:  "identifiers",
			input: "github steps_foo bar123",
			expect: []Token{
				{Kind: TokenIdent, Value: "github", Offset: 0},
				{Kind: TokenIdent, Value: "steps_foo", Offset: 7},
				{Kind: TokenIdent, Value: "bar123", Offset: 17},
				{Kind: TokenEOF, Offset: 23},
			},
		},
		{
			name:  "hyphenated identifier",
			input: "fail-fast",
			expect: []Token{
				{Kind: TokenIdent, Value: "fail-fast", Offset: 0},
				{Kind: TokenEOF, Offset: 9},
			},
		},
		{
			name:  "keywords",
			input: "true false null",
			expect: []Token{
				{Kind: TokenTrue, Value: "true", Offset: 0},
				{Kind: TokenFalse, Value: "false", Offset: 5},
				{Kind: TokenNull, Value: "null", Offset: 11},
				{Kind: TokenEOF, Offset: 15},
			},
		},
		{
			name:  "integers",
			input: "42 0 0xff 0xFF",
			expect: []Token{
				{Kind: TokenInt, Value: "42", Offset: 0},
				{Kind: TokenInt, Value: "0", Offset: 3},
				{Kind: TokenInt, Value: "0xff", Offset: 5},
				{Kind: TokenInt, Value: "0xFF", Offset: 10},
				{Kind: TokenEOF, Offset: 14},
			},
		},
		{
			name:  "floats",
			input: "3.14 2.99e-2 1.5E10",
			expect: []Token{
				{Kind: TokenFloat, Value: "3.14", Offset: 0},
				{Kind: TokenFloat, Value: "2.99e-2", Offset: 5},
				{Kind: TokenFloat, Value: "1.5E10", Offset: 13},
				{Kind: TokenEOF, Offset: 19},
			},
		},
		{
			name:  "strings",
			input: "'hello' 'it''s' ''",
			expect: []Token{
				{Kind: TokenString, Value: "hello", Offset: 0},
				{Kind: TokenString, Value: "it's", Offset: 8},
				{Kind: TokenString, Value: "", Offset: 16},
				{Kind: TokenEOF, Offset: 18},
			},
		},
		{
			name:  "whitespace skipping",
			input: "  \t\n  42  \r\n  true  ",
			expect: []Token{
				{Kind: TokenInt, Value: "42", Offset: 6},
				{Kind: TokenTrue, Value: "true", Offset: 14},
				{Kind: TokenEOF, Offset: 20},
			},
		},
		{
			name:  "full expression",
			input: "github.event == 'push' && contains(matrix.os, 'ubuntu')",
			expect: []Token{
				{Kind: TokenIdent, Value: "github", Offset: 0},
				{Kind: TokenDot, Value: ".", Offset: 6},
				{Kind: TokenIdent, Value: "event", Offset: 7},
				{Kind: TokenEQ, Value: "==", Offset: 13},
				{Kind: TokenString, Value: "push", Offset: 16},
				{Kind: TokenAnd, Value: "&&", Offset: 23},
				{Kind: TokenIdent, Value: "contains", Offset: 26},
				{Kind: TokenLParen, Value: "(", Offset: 34},
				{Kind: TokenIdent, Value: "matrix", Offset: 35},
				{Kind: TokenDot, Value: ".", Offset: 41},
				{Kind: TokenIdent, Value: "os", Offset: 42},
				{Kind: TokenComma, Value: ",", Offset: 44},
				{Kind: TokenString, Value: "ubuntu", Offset: 46},
				{Kind: TokenRParen, Value: ")", Offset: 54},
				{Kind: TokenEOF, Offset: 55},
			},
		},
		{
			name:  "integer then dot ident not float",
			input: "42.name",
			expect: []Token{
				{Kind: TokenInt, Value: "42", Offset: 0},
				{Kind: TokenDot, Value: ".", Offset: 2},
				{Kind: TokenIdent, Value: "name", Offset: 3},
				{Kind: TokenEOF, Offset: 7},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := collectTokens(tt.input)
			require.Equal(t, len(tt.expect), len(tokens))
			for i, want := range tt.expect {
				assert.Equal(t, want.Kind, tokens[i].Kind, "token %d kind", i)
				assert.Equal(t, want.Value, tokens[i].Value, "token %d value", i)
				assert.Equal(t, want.Offset, tokens[i].Offset, "token %d offset", i)
			}
		})
	}
}

func TestLexerErrors(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErrMsg string
		wantErrOff int
	}{
		{
			name:       "unterminated string",
			input:      "'hello",
			wantErrMsg: "unterminated string literal",
			wantErrOff: 0,
		},
		{
			name:       "unknown character tilde",
			input:      "~",
			wantErrMsg: `unexpected character "~"`,
			wantErrOff: 0,
		},
		{
			name:       "double quote",
			input:      `"`,
			wantErrMsg: `unexpected character "\""`,
			wantErrOff: 0,
		},
		{
			name:       "lone equals",
			input:      "a = b",
			wantErrMsg: "unexpected character '='",
			wantErrOff: 2,
		},
		{
			name:       "lone ampersand",
			input:      "a & b",
			wantErrMsg: "unexpected character '&'",
			wantErrOff: 2,
		},
		{
			name:       "lone pipe",
			input:      "a | b",
			wantErrMsg: "unexpected character '|'",
			wantErrOff: 2,
		},
		{
			name:       "invalid hex literal",
			input:      "0x",
			wantErrMsg: "invalid hex literal: expected digits after '0x'",
			wantErrOff: 0,
		},
		{
			name:       "invalid exponent no digits",
			input:      "1e",
			wantErrMsg: "invalid number: expected digits after exponent",
			wantErrOff: 0,
		},
		{
			name:       "invalid exponent with sign no digits",
			input:      "1e+",
			wantErrMsg: "invalid number: expected digits after exponent",
			wantErrOff: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLexer(tt.input)
			// consume all tokens to trigger errors
			for {
				tok := l.next()
				if tok.Kind == TokenEOF {
					break
				}
			}
			require.NotEmpty(t, l.errors, "expected lexer errors")
			assert.Equal(t, tt.wantErrMsg, l.errors[0].Message)
			assert.Equal(t, tt.wantErrOff, l.errors[0].Offset)
		})
	}
}

func TestParse(t *testing.T) {
	valid := []struct {
		name  string
		input string
	}{
		// Literals
		{name: "string literal", input: "'hello'"},
		{name: "empty string", input: "''"},
		{name: "integer", input: "42"},
		{name: "hex integer", input: "0xFF"},
		{name: "float", input: "3.14"},
		{name: "float with exponent", input: "2.99e-2"},
		{name: "true", input: "true"},
		{name: "false", input: "false"},
		{name: "null", input: "null"},

		// Property access
		{name: "dot access", input: "github.event"},
		{name: "deep dot access", input: "github.event.action"},
		{name: "bracket access", input: "github['event']"},
		{name: "wildcard", input: "steps.*.outputs.result"},
		{name: "mixed access", input: "matrix['os']"},

		// Operators
		{name: "equality", input: "a == b"},
		{name: "inequality", input: "a != b"},
		{name: "less than", input: "a < b"},
		{name: "less than or equal", input: "a <= b"},
		{name: "greater than", input: "a > b"},
		{name: "greater than or equal", input: "a >= b"},
		{name: "and", input: "a && b"},
		{name: "or", input: "a || b"},
		{name: "not", input: "!a"},
		{name: "double not", input: "!!a"},

		// Grouping
		{name: "parens", input: "(a || b) && c"},
		{name: "nested parens", input: "((a))"},

		// Function calls
		{name: "zero args", input: "always()"},
		{name: "one arg", input: "success()"},
		{name: "one arg with value", input: "contains('hello', 'ell')"},
		{name: "two args", input: "startsWith(github.ref, 'refs/')"},
		{name: "many args", input: "format('{0} {1}', a, b)"},
		{name: "case function", input: "hashFiles('**/package-lock.json')"},

		// Complex expressions
		{name: "complex and/or", input: "github.event_name == 'push' && github.ref == 'refs/heads/main'"},
		{name: "complex with function", input: "contains(github.event.head_commit.message, '[skip ci]') || github.event_name == 'pull_request'"},
		{name: "nested function", input: "contains(fromJSON(steps.changes.outputs.packages), matrix.package)"},
		{name: "comparison chain", input: "a == b && c != d || e < f"},
		{name: "not with comparison", input: "!cancelled() && success()"},
		{name: "bracket with expression", input: "env[github.event.action]"},

		// Function call followed by postfix access
		{name: "function then dot", input: "fromJSON(steps.x.outputs.y).key"},
		{name: "function then bracket", input: "toJSON(matrix)['os']"},
		{name: "integer then dot ident", input: "42"},
	}

	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			errs := Parse(tt.input)
			assert.Empty(t, errs, "expected no errors for: %s", tt.input)
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErrMsg string
	}{
		{
			name:       "empty input",
			input:      "",
			wantErrMsg: "expected expression, but got end of input",
		},
		{
			name:       "leading operator",
			input:      "== a",
			wantErrMsg: "expected expression, but got '=='",
		},
		{
			name:       "incomplete comparison",
			input:      "a ==",
			wantErrMsg: "expected expression after '=='",
		},
		{
			name:       "incomplete and",
			input:      "a &&",
			wantErrMsg: "expected expression after '&&'",
		},
		{
			name:       "incomplete or",
			input:      "a ||",
			wantErrMsg: "expected expression after '||'",
		},
		{
			name:       "incomplete not",
			input:      "!",
			wantErrMsg: "expected expression after '!'",
		},
		{
			name:       "trailing token",
			input:      "a b",
			wantErrMsg: "unexpected token 'b' after expression",
		},
		{
			name:       "unclosed paren",
			input:      "(a",
			wantErrMsg: "expected ')', but got end of input",
		},
		{
			name:       "unclosed function",
			input:      "foo(a",
			wantErrMsg: "expected ')' after function arguments, but got end of input",
		},
		{
			name:       "unclosed bracket",
			input:      "a[0",
			wantErrMsg: "expected ']', but got end of input",
		},
		{
			name:       "unterminated string",
			input:      "'hello",
			wantErrMsg: "unterminated string literal",
		},
		{
			name:       "double quote",
			input:      `"hello"`,
			wantErrMsg: `unexpected character "\""`,
		},
		{
			name:       "unknown character",
			input:      "~",
			wantErrMsg: `unexpected character "~"`,
		},
		{
			name:       "incomplete lt",
			input:      "a <",
			wantErrMsg: "expected expression after '<'",
		},
		{
			name:       "incomplete gt",
			input:      "a >",
			wantErrMsg: "expected expression after '>'",
		},
		{
			name:       "incomplete ne",
			input:      "a !=",
			wantErrMsg: "expected expression after '!='",
		},
		{
			name:       "empty function EOF",
			input:      "foo(",
			wantErrMsg: "expected expression or ')' in function call, but got end of input",
		},
		{
			name:       "trailing comma in function",
			input:      "contains(a, )",
			wantErrMsg: "expected expression, but got ')'",
		},
		{
			name:       "empty bracket access",
			input:      "a[]",
			wantErrMsg: "expected expression, but got ']'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := Parse(tt.input)
			require.NotEmpty(t, errs, "expected errors for: %s", tt.input)
			assert.Contains(t, errs[0].Message, tt.wantErrMsg)
		})
	}
}

func TestExtractExpressions(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantSpans []Span
		wantErrs  int
	}{
		{
			name:      "no expressions",
			input:     "just a plain string",
			wantSpans: nil,
			wantErrs:  0,
		},
		{
			name:  "single expression",
			input: "${{ github.event_name }}",
			wantSpans: []Span{
				{Start: 0, End: 24, Inner: " github.event_name "},
			},
			wantErrs: 0,
		},
		{
			name:  "embedded expression",
			input: "hello-${{ github.actor }}-world",
			wantSpans: []Span{
				{Start: 6, End: 25, Inner: " github.actor "},
			},
			wantErrs: 0,
		},
		{
			name:  "multiple expressions",
			input: "${{ a }}-${{ b }}",
			wantSpans: []Span{
				{Start: 0, End: 8, Inner: " a "},
				{Start: 9, End: 17, Inner: " b "},
			},
			wantErrs: 0,
		},
		{
			name:      "unterminated expression",
			input:     "${{ oops",
			wantSpans: nil,
			wantErrs:  1,
		},
		{
			name:      "bare opener no content",
			input:     "${{",
			wantSpans: nil,
			wantErrs:  1,
		},
		{
			name:  "closing braces inside string literal",
			input: "${{ contains('}}', x) }}",
			wantSpans: []Span{
				{Start: 0, End: 24, Inner: " contains('}}', x) "},
			},
			wantErrs: 0,
		},
		{
			name:  "escaped quote before closing braces",
			input: "${{ contains('it''s }}', x) }}",
			wantSpans: []Span{
				{Start: 0, End: 30, Inner: " contains('it''s }}', x) "},
			},
			wantErrs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans, errs := ExtractExpressions(tt.input)
			assert.Equal(t, tt.wantSpans, spans)
			assert.Len(t, errs, tt.wantErrs)
		})
	}
}
