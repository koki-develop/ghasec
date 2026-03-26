# expression/CLAUDE.md

## Overview

`expression` package implements a hand-rolled lexer and recursive descent parser for GitHub Actions `${{ }}` expression syntax. It provides extraction of expression spans from string values and syntax validation of expression contents.

## Architecture

The package has six files:

- `expression.go` — public API: `ExtractExpressions` and `Parse`.
- `token.go` — `TokenKind` enum and `Token` struct.
- `lexer.go` — hand-rolled lexer that tokenizes expression content.
- `parser.go` — recursive descent parser that builds an AST.
- `ast.go` — AST node type definitions.
- `walk.go` — `Walk` function for AST traversal.

## Key API

- `ExtractExpressions(value string) ([]Span, []Error)` — finds all `${{ ... }}` spans in a string value. Handles single-quote string literals inside expressions (with `''` escape). Returns spans (with `Start`, `End`, `Inner`) and extraction-level errors (e.g. unterminated expressions).
- `Parse(input string) (Node, []Error)` — parses the content between `${{` and `}}`, returns an AST and any syntax errors. On error, `Node` is nil.
- `Walk(node Node, fn func(Node) bool)` — pre-order AST traversal. If `fn` returns false, children are skipped.
- `Span` — represents a single `${{ ... }}` expression found in a string (`Start`, `End`, `Inner`).
- `Error` — syntax error with `Offset` (position within the expression) and `Message`.

## Lexer

Tokenizes expression content into: identifiers, integers (decimal and hex), floats, string literals (single-quoted with `''` escape), boolean/null keywords, operators (`==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`), punctuation (`(`, `)`, `[`, `]`, `.`, `*`, `,`). Whitespace is skipped. Invalid characters produce errors and are skipped (the lexer continues).

## Parser

Recursive descent with this precedence (lowest to highest):

1. `||` (logical OR)
2. `&&` (logical AND)
3. `==`, `!=` (equality)
4. `<`, `<=`, `>`, `>=` (comparison)
5. `!` (unary NOT)
6. Primary: literals, identifiers, function calls, parenthesized expressions

Postfix operators: `.property`, `.*` (filter), `[index]`.

The parser builds an AST (defined in `ast.go`) and validates syntax — no semantic checks (type checking, function existence, context variable resolution). Errors from both the lexer and parser are combined in the result. All AST nodes carry an `Offset` field (byte offset within the expression string) for precise error positioning.

## AST Node Types

- `BinaryNode` — binary operators (`==`, `!=`, `&&`, `||`, `<`, `<=`, `>`, `>=`)
- `UnaryNode` — unary `!`
- `IdentNode` — identifiers (e.g., `github`)
- `PropertyAccessNode` — dot access (e.g., `github.actor`)
- `IndexAccessNode` — bracket access (e.g., `matrix['os']`)
- `FilterNode` — star filter (e.g., `steps.*.outcome`)
- `LiteralNode` — string, int, float, true, false, null
- `FunctionCallNode` — function calls (e.g., `contains(...)`)
- `ParenNode` — parenthesized expressions

## Usage Context

- Used by the `invalid-expression` rule for syntax checking.
- Used by `rules/helpers.go` (`IsExpressionNode`, `ExpressionSpanToken`, `ExpressionSpanTokens`) for expression detection and span extraction.
- Used by the `actor-bot-check` rule for AST-based pattern detection (parses expressions and walks the AST to find `github.actor` bot comparisons).
- Expression-position checks (forbidding `${{ }}` in static fields) live in the required rules, not in `invalid-expression`.
