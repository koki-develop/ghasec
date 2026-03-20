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
```

## Architecture

The pipeline flows: **discover -> parse -> analyze (rules) -> diagnostic output**.

- `cmd/root.go` — CLI entry point (cobra). Orchestrates the full pipeline.
- `analyzer/` — Runs rules against a parsed AST file. Required rules run first; if any fail, non-required rules are skipped entirely.
- `renderer/` — Diagnostic error rendering with source annotation, syntax highlighting, `NO_COLOR` support, and automatic ancestor breadcrumb computation from token positions.
- `workflow/` — Typed wrappers around `goccy/go-yaml` AST nodes and `ActionRef` for action references. Rules use these wrappers for domain-specific navigation.
- `rules/` — See `rules/CLAUDE.md` for details. `invalid-workflow` and `invalid-action` are required rules (structural validation).
- `e2e/` — E2E tests. See `e2e/CLAUDE.md` for details.

## Key Design Decisions

- Tests use `github.com/stretchr/testify` (assert/require).
- Supports `NO_COLOR` environment variable to disable ANSI styling ([no-color.org](https://no-color.org) compliant).
