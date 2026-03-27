# workflow/CLAUDE.md

## Overview

`workflow` package provides typed wrappers around `goccy/go-yaml` AST nodes for domain-specific navigation of GitHub Actions workflow and action files. Rules operate on these wrappers rather than raw AST nodes.

## Type Hierarchy

- `Mapping` — wraps `*ast.MappingNode`. Provides `FindKey(key)` for key lookup and `FirstToken()` to get the first non-comment token in the file.
- `WorkflowMapping` — embeds `Mapping`. Represents the top-level workflow document. Provides `EachJob(fn)` to iterate over all jobs and `EachStep(fn)` to iterate over all steps across all jobs. `EachStep` delegates to `EachJob` internally.
- `ActionMapping` — embeds `Mapping`. Represents the top-level action metadata document. Provides `EachStep(fn)` to iterate over steps in a composite action's `runs.steps`.
- `JobMapping` — embeds `Mapping`. Represents a job-level mapping.
- `StepMapping` — embeds `Mapping`. Represents a step-level mapping. Provides `Uses()` to extract `ActionRef` and `With()` to access the `with` mapping.

## ActionRef

`ActionRef` holds a step's `uses` value together with its source token. It provides:

- `String()` — raw value (e.g. `actions/checkout@abc123`).
- `Token()` / `RefToken()` — source token for the full value or just the ref portion (after `@`). `RefToken` creates a synthetic token with adjusted column/offset for precise caret placement on the ref.
- `Ref()` — git reference portion after `@` (as `git.Ref`).
- `OwnerRepo()` — extracts owner and repo from the action path.
- `IsLocal()` / `IsDocker()` — type checks for local path (`./`) and Docker (`docker://`) references.

## Design Notes

- `EachStep` methods silently skip malformed sections (missing jobs, non-mapping nodes, etc.) because structural validation is handled by the required `invalid-workflow` / `invalid-action` rules, which gate all non-required rules.
- `FirstToken` skips leading comment tokens so file-level errors point to actual YAML content. It returns a copy with `Value` trimmed to 1 byte to produce a single-character caret marker.
