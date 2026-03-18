# rules/CLAUDE.md

## Overview

`rules/` package defines the `Rule` interface (`ID()`, `Required()`, `Check()`). Helper functions `TopLevelMapping` and `FindKey` navigate the `goccy/go-yaml` AST.

## Existing Rules

- `rules/invalid-workflow/` — **Required** rule (`package invalidworkflow`). Validates workflow structure (requires `on` and `jobs`, validates job fields like `runs-on`/`uses`/`steps`).
- `rules/unpinned-action/` — **Non-required** rule (`package unpinnedaction`). Checks that third-party action references are pinned to full-length commit SHAs.
- `rules/checkout-persist-credentials/` — **Non-required** rule (`package checkoutpersistcredentials`). Checks that `actions/checkout` steps include `persist-credentials: false`.
- `rules/default-permissions/` — **Non-required** rule (`package defaultpermissions`). Checks that workflow-level `permissions` is set to `{}`.
- `rules/mismatched-sha-tag/` — **Non-required** rule (`package mismatchedshatag`). Verifies that a commit SHA pinned in an action reference matches the tag in its inline comment via the GitHub API.

## Key Design Decisions

- Uses `goccy/go-yaml` AST (not `gopkg.in/yaml.v3`) — all rule checks operate on `ast.MappingNode`, `ast.SequenceNode`, etc.
- Rules are two-phase: required rules (structural validation) gate non-required rules (lint checks). This prevents noisy lint errors on malformed files.
- New rules: implement `rules.Rule` interface and register in `cmd/root.go`'s `analyzer.New(...)` call. Rule IDs are flat kebab-case names describing the violation they detect (e.g., `invalid-workflow`, `unpinned-action`).
- Tests use `github.com/stretchr/testify` (assert/require).
