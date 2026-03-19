# rules/CLAUDE.md

## Overview

`rules/` package defines the `Rule` interface (`ID()`, `Required()`, `Online()`, `Check()`). `Check` receives a `workflow.WorkflowMapping` (the top-level workflow mapping, extracted by the analyzer). AST navigation helpers live in the `workflow` package as methods on typed wrappers:

- `Mapping.FindKey` — finds a key in a mapping node.
- `Mapping.FirstToken` — walks the token chain to the first token in the file.
- `WorkflowMapping.EachStep` — iterates over all steps across all jobs.
- `StepMapping.Uses` — extracts an `ActionRef` from a step's `uses` key.
- `ActionRef.IsLocal` / `ActionRef.IsDocker` — classify action reference types.
- `ActionRef.Ref` — returns the git ref portion after `@`.
- `ActionRef.OwnerRepo` — extracts owner and repo from the action path.

## Existing Rules

- `rules/invalid-workflow/` — **Required** rule (`package invalidworkflow`). Validates workflow structure (requires `on` and `jobs`, validates job fields like `runs-on`/`uses`/`steps`).
- `rules/unpinned-action/` — **Non-required** rule (`package unpinnedaction`). Checks that third-party action references are pinned to full-length commit SHAs.
- `rules/checkout-persist-credentials/` — **Non-required** rule (`package checkoutpersistcredentials`). Checks that `actions/checkout` steps include `persist-credentials: false`.
- `rules/default-permissions/` — **Non-required** rule (`package defaultpermissions`). Checks that workflow-level `permissions` is set to `{}`.
- `rules/mismatched-sha-tag/` — **Non-required, online** rule (`package mismatchedshatag`). Verifies that a commit SHA pinned in an action reference matches the tag in its inline comment via the GitHub API. Requires `--online` flag.

## Key Design Decisions

- Uses `goccy/go-yaml` AST (not `gopkg.in/yaml.v3`) — all rule checks operate on typed wrappers from the `workflow` package (`workflow.WorkflowMapping`, `workflow.JobMapping`, `workflow.StepMapping`) which embed `workflow.Mapping` (wrapping `*ast.MappingNode`). The analyzer extracts the top-level mapping from `*ast.File` and passes it to each rule's `Check(workflow.WorkflowMapping)` method; rules never see `*ast.File` directly.
- Rules are two-phase: required rules (structural validation) gate non-required rules (lint checks). This prevents noisy lint errors on malformed files.
- Online rules (`Online() == true`) require network access and are disabled by default. They run only when `--online` is passed. Currently only `mismatched-sha-tag` is an online rule.
- New rules: implement `rules.Rule` interface and register in `cmd/root.go`'s `analyzer.New(...)` call. Rule IDs are flat kebab-case names describing the violation they detect (e.g., `invalid-workflow`, `unpinned-action`).
- Tests use `github.com/stretchr/testify` (assert/require).
