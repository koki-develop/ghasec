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
go test -count=1 ./e2e/...   # E2E tests without cache (use when cached results are stale)

# Code generation (after updating SchemaStore submodule)
go generate ./rules/invalid-workflow/ ./rules/invalid-action/
```

## Architecture

The pipeline flows: **discover -> parse -> analyze (rules) -> diagnostic output**.

- `cmd/root.go` — CLI entry point (cobra). Orchestrates the full pipeline.
- `cmd/gen/` — Code generator. Reads JSON Schema from SchemaStore submodule, emits Go validation code. Output: `rules/invalid-workflow/generated.go` and `rules/invalid-action/generated.go`.
- `analyzer/` — Rule execution and diagnostic filtering. See `analyzer/CLAUDE.md`.
- `renderer/` — Diagnostic error rendering with source annotation. See `renderer/CLAUDE.md`.
- `workflow/` — Typed AST wrappers for workflow/action navigation. See `workflow/CLAUDE.md`.
- `expression/` — Lexer and parser for `${{ }}` expression syntax. See `expression/CLAUDE.md`.
- `rules/` — Pluggable validation rules. See `rules/CLAUDE.md`.
- `e2e/` — E2E tests. See `e2e/CLAUDE.md`.

## Key Design Decisions

- Tests use `github.com/stretchr/testify` (assert/require).
- Supports `NO_COLOR` environment variable to disable ANSI styling ([no-color.org](https://no-color.org) compliant).
