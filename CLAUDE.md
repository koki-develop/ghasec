# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ghasec is a security linter for GitHub Actions workflow files. It parses `.github/workflows/*.yml|yaml` files and runs pluggable validation rules against the YAML AST.

## Commands

```bash
# Build
go build -o ghasec .

# Run
go run . [files...]           # Lint specific files
go run .                      # Auto-discover .github/workflows/*.yml|yaml

# Test
go test ./...                 # All tests (unit + E2E)
go test ./rules/unpinned-action/...  # Single package
go test -run TestName ./pkg/  # Single test
go test ./e2e/...             # E2E tests only
```

## Architecture

The pipeline flows: **discover -> parse -> analyze (rules) -> diagnostic output**.

- `cmd/root.go` — CLI entry point (cobra). Orchestrates the full pipeline: resolve files, parse, run analyzer, print errors with source annotations via `annotate-go`.
- `discover/` — Finds workflow files under `.github/workflows/`.
- `parser/` — Thin wrapper around `goccy/go-yaml/parser` to parse YAML into AST.
- `analyzer/` — Takes a list of `rules.Rule` and runs them against a parsed AST file. Required rules run first; if any fail, non-required rules are skipped entirely.
- `rules/` — See `rules/CLAUDE.md` for details.
- `diagnostic/` — `Error` type carrying a `token.Token` (for source location) and message.
- `e2e/` — E2E tests. See `e2e/CLAUDE.md` for details.

## Key Design Decisions

- Tests use `github.com/stretchr/testify` (assert/require).
- Supports `NO_COLOR` environment variable to disable ANSI styling ([no-color.org](https://no-color.org) compliant).
