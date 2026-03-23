# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ghasec is a security linter for GitHub Actions workflow files (`.github/workflows/*.yml|yaml`) and action definition files (`action.yml`/`action.yaml`). It parses these files and runs pluggable validation rules against the YAML AST.

## Commands

```bash
# Build
go build -o ghasec .

# Run
go run . [files...]           # Lint specific files
go run .                      # Auto-discover .github/workflows/*.yml|yaml and **/action.yml|yaml

# Test
go test ./...                 # All tests (unit + E2E)
go test ./rules/unpinned-action/...  # Single package
go test -run TestName ./pkg/  # Single test
go test ./e2e/...             # E2E tests only

# Code generation (after updating SchemaStore submodule)
go generate ./rules/invalid-workflow/ ./rules/invalid-action/
```

## Architecture

The pipeline flows: **discover -> parse -> analyze (rules) -> diagnostic output**.

- `cmd/root.go` — CLI entry point (cobra). Orchestrates the full pipeline.
- `cmd/gen/` — Code generator. Reads JSON Schema from SchemaStore submodule (`schemastore/`), converts to IR, emits Go validation code via `text/template`. Also extracts per-event activity type enums from the raw JSON schema (lost during compilation due to draft-07 `$ref` sibling behavior). Output: `rules/invalid-workflow/generated.go` and `rules/invalid-action/generated.go`.
- `analyzer/` — Runs rules against a parsed AST file. Required rules run first; if any fail, non-required rules are skipped entirely.
- `renderer/` — Diagnostic error rendering with source annotation, syntax highlighting, `NO_COLOR` support, and automatic ancestor breadcrumb computation from token positions.
- `workflow/` — Typed wrappers around `goccy/go-yaml` AST nodes and `ActionRef` for action references. Rules use these wrappers for domain-specific navigation.
- `expression/` — Hand-rolled lexer and recursive descent parser for GitHub Actions `${{ }}` expression syntax. Provides `ExtractExpressions` (finds `${{ }}` spans in strings, quote-aware) and `Parse` (validates expression syntax). Used by the `invalid-expression` rule for syntax checking and by `rules/helpers.go` for expression-position detection.
- `rules/` — See `rules/CLAUDE.md` for details. `invalid-workflow` and `invalid-action` are required rules (structural validation). These use a mix of schema-generated validation (unknown keys, required fields, type/enum checks) and hand-written checks (mutual exclusion, step validation, expression position validation, domain-specific messages).
- `e2e/` — E2E tests. See `e2e/CLAUDE.md` for details.

## Key Design Decisions

- Tests use `github.com/stretchr/testify` (assert/require).
- Supports `NO_COLOR` environment variable to disable ANSI styling ([no-color.org](https://no-color.org) compliant).
