# rules/CLAUDE.md

## Overview

`rules/` package defines the `Rule` interface (`ID()`, `Required()`, `Online()`, `Check()`). `Check` receives a `workflow.WorkflowMapping` (the top-level workflow mapping, extracted by the analyzer). AST navigation helpers live in the `workflow` package as methods on typed wrappers — see `workflow/` source for the full API.

## Existing Rules

Each rule lives in its own subdirectory under `rules/`. Run `ls rules/` to see all rules. Notable distinctions:

- `invalid-workflow` is the only **required** rule (structural validation). All others are non-required (lint checks).
- `mismatched-sha-tag` is the only **online** rule (requires `--online` flag).

## Key Design Decisions

- Uses `goccy/go-yaml` AST (not `gopkg.in/yaml.v3`) — all rule checks operate on typed wrappers from the `workflow` package (`workflow.WorkflowMapping`, `workflow.JobMapping`, `workflow.StepMapping`) which embed `workflow.Mapping` (wrapping `*ast.MappingNode`). The analyzer extracts the top-level mapping from `*ast.File` and passes it to each rule's `Check(workflow.WorkflowMapping)` method; rules never see `*ast.File` directly.
- Rules are two-phase: required rules (structural validation) gate non-required rules (lint checks). This prevents noisy lint errors on malformed files.
- Online rules (`Online() == true`) require network access and are disabled by default. They run only when `--online` is passed. Currently only `mismatched-sha-tag` is an online rule.
- New rules: implement `rules.Rule` interface and add to the `buildRules()` function in `cmd/root.go`. Online rules should lazily initialize their own dependencies (see `mismatched-sha-tag` for an example). Rule IDs are flat kebab-case names describing the violation they detect (e.g., `invalid-workflow`, `unpinned-action`).
- Tests use `github.com/stretchr/testify` (assert/require).
