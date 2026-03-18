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
go test ./rules/shapin/...    # Single package
go test -run TestName ./pkg/  # Single test
go test ./e2e/...             # E2E tests only
```

## Architecture

The pipeline flows: **discover -> parse -> analyze (rules) -> diagnostic output**.

- `cmd/root.go` — CLI entry point (cobra). Orchestrates the full pipeline: resolve files, parse, run analyzer, print errors with source annotations via `annotate-go`.
- `discover/` — Finds workflow files under `.github/workflows/`.
- `parser/` — Thin wrapper around `goccy/go-yaml/parser` to parse YAML into AST.
- `analyzer/` — Takes a list of `rules.Rule` and runs them against a parsed AST file. Required rules run first; if any fail, non-required rules are skipped entirely.
- `rules/` — Defines the `Rule` interface (`ID()`, `Required()`, `Check()`). Helper functions `TopLevelMapping` and `FindKey` for navigating the `goccy/go-yaml` AST.
  - `rules/workflow/` — **Required** rule. Validates workflow structure (requires `on` and `jobs`, validates job fields like `runs-on`/`uses`/`steps`).
  - `rules/shapin/` — **Non-required** rule. Checks that third-party action references are pinned to full-length commit SHAs.
- `diagnostic/` — `Error` type carrying a `token.Token` (for source location) and message.
- `e2e/` — E2E tests. Builds binary once in `TestMain`, runs each `testdata/` subdirectory as a test case. Each case has `workflows/` (input YAML) and `expected.yml` (expected exit code, stdout, stderr). Test data is embedded via `go:embed`. Adding a test case only requires adding a new directory — no Go code changes needed.

## Key Design Decisions

- Uses `goccy/go-yaml` AST (not `gopkg.in/yaml.v3`) — all rule checks operate on `ast.MappingNode`, `ast.SequenceNode`, etc.
- Rules are two-phase: required rules (structural validation) gate non-required rules (lint checks). This prevents noisy lint errors on malformed files.
- New rules: implement `rules.Rule` interface and register in `cmd/root.go`'s `analyzer.New(...)` call. Rule IDs are flat kebab-case names describing the violation they detect (e.g., `invalid-workflow`, `unpinned-action`).
- Tests use `github.com/stretchr/testify` (assert/require).
- Supports `NO_COLOR` environment variable to disable ANSI styling ([no-color.org](https://no-color.org) compliant).
