# expression/CLAUDE.md

## Overview

`expression` package implements a hand-rolled lexer and recursive descent parser for GitHub Actions `${{ }}` expression syntax. It provides extraction of expression spans from string values and syntax validation of expression contents.

## Architecture

The package has four files:

- `expression.go` — public API: `ExtractExpressions` and `Parse`.
- `token.go` — `TokenKind` enum and `Token` struct.
- `lexer.go` — hand-rolled lexer that tokenizes expression content.
- `parser.go` — recursive descent parser that validates expression syntax.

## Key API

- `ExtractExpressions(value string) ([]Span, []Error)` — finds all `${{ ... }}` spans in a string value. Handles single-quote string literals inside expressions (with `''` escape). Returns spans (with `Start`, `End`, `Inner`) and extraction-level errors (e.g. unterminated expressions).
- `Parse(input string) []Error` — parses the content between `${{` and `}}` and validates syntax. Returns nil if valid.
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

The parser validates syntax only — no semantic checks (type checking, function existence, context variable resolution). Errors from both the lexer and parser are combined in the result.

## Usage Context

- Used by the `invalid-expression` rule for syntax checking.
- Used by `rules/helpers.go` (`ContainsExpression`, `IsExpression`) for expression-position detection.
- Expression-position checks (forbidding `${{ }}` in static fields) live in the required rules, not in `invalid-expression`.
