# rules/CLAUDE.md

## Overview

`rules/` package defines the `Rule` interface with metadata methods (`ID()`, `Required()`, `Online()`). Rules implement `WorkflowRule` (`CheckWorkflow(workflow.WorkflowMapping)`), `ActionRule` (`CheckAction(workflow.ActionMapping)`), or both, depending on which file types they validate. The analyzer dispatches to the appropriate check method based on file type. AST navigation helpers live in the `workflow` package as methods on typed wrappers — see `workflow/` source for the full API.

## Existing Rules

Each rule lives in its own subdirectory under `rules/`. Run `ls rules/` to see all rules. Notable distinctions:

- `invalid-workflow` and `invalid-action` are **required** rules (structural validation). All others are non-required (lint checks).
- `invalid-expression` is a **non-required** rule that validates `${{ }}` expression syntax (Phase 1: syntax only, no semantic checks). It also detects bare `if:` expressions without `${{ }}` wrappers. Expression-position checks (forbidding `${{ }}` in static fields like `steps[].id`, `permissions`, `on.*` config) live in the required rules (`invalid-workflow`/`invalid-action`), not in `invalid-expression`.
- `mismatched-sha-tag` is the only **online** rule (requires `--online` flag).

## Ignore Directives

Users can suppress diagnostics with `# ghasec-ignore[:rule-id,...]` comments (inline or previous-line). The `ignore` package parses these; the `analyzer` filters diagnostics accordingly. Individual rules do not need to handle ignore directives — filtering is centralized in the analyzer.

- Required rules (`invalid-workflow`, `invalid-action`) cannot be ignored.
- Unused or invalid ignore directives produce `unused-ignore` diagnostics.
- `unused-ignore` is not a real `Rule` implementation — it is a RuleID string set directly by the analyzer.

See `rules/unused-ignore/README.md` for full syntax documentation.

## Key Design Decisions

- Uses `goccy/go-yaml` AST (not `gopkg.in/yaml.v3`) — all rule checks operate on typed wrappers from the `workflow` package (`workflow.WorkflowMapping`, `workflow.ActionMapping`, `workflow.JobMapping`, `workflow.StepMapping`) which embed `workflow.Mapping` (wrapping `*ast.MappingNode`). The analyzer extracts the top-level mapping from `*ast.File` and passes it to each rule's check method; rules never see `*ast.File` directly.
- `invalid-workflow` and `invalid-action` use **generated code as the base** (`generated.go` from `cmd/gen/`). Hand-written code in `extensions.go` / `invalid_action.go` only **adds** validations that JSON Schema cannot express (mutual exclusion, uniqueness constraints, cross-property references, cycle detection, etc.). Never skip or filter generated code output.
- Rules are two-phase: required rules (structural validation) gate non-required rules (lint checks). This prevents noisy lint errors on malformed files.
- Online rules (`Online() == true`) require network access and are disabled by default. They run only when `--online` is passed. Currently only `mismatched-sha-tag` is an online rule.
- New rules: implement `rules.Rule` interface plus `WorkflowRule`, `ActionRule`, or both, and add to the `buildRules()` function in `cmd/root.go`. Online rules should lazily initialize their own dependencies (see `mismatched-sha-tag` for an example). Rule IDs are flat kebab-case names describing the violation they detect (e.g., `invalid-workflow`, `unpinned-action`).
- Tests use `github.com/stretchr/testify` (assert/require).

## Diagnostic Context (Breadcrumbs)

The renderer automatically computes ancestor breadcrumb lines from the error token's position — rules do NOT manually specify parent keys. The renderer walks backward through the token chain collecting mapping keys and sequence entries at decreasing indentation levels.

Rules only need to set `Token` and `Message` on `diagnostic.Error`. Use `ExtraContexts` only for non-ancestor tokens that provide important context (e.g., `default-permissions` uses it to show the last permission entry, `checkout-persist-credentials` uses it to show the `uses` value when the error is on `persist-credentials`).

For diagnostics pointing to a `${{ }}` span within a larger string, use `rules.ExpressionSpanToken` to create a synthetic token covering only the expression span (not the entire YAML string value). It takes the `ast.Node` (not a raw token) so it can detect block scalars (`|` / `>`) and compute correct line/column positions for multiline values. For inline/quoted strings, it adjusts the column with quote offset correction.

## Diagnostic Message Format

Messages use **key-path subject style** — the YAML key or structural term is the subject of the sentence. When a mapping entry itself is the subject (e.g., a specific job, input, or output), include the entry's key name: `job "<id>" must be ...`, `input "<name>" must be ...`. For keys within an entry, the annotated source output provides positional context — no extra prefix needed.

**Patterns:**
- Required key: `"<key>" is required` (single), `"<a>" or "<b>" is required` (alternatives)
- Mutual exclusion: `"<a>" and "<b>" are mutually exclusive`
- Type mismatch: `"<key>" must be a <type>, but got <actual>` (always include `but got`)
- Unknown identifier: `unknown key "<key>"` (no static parent) or `"<parent>" has unknown <thing> "<name>"` (static parent)
- Sequence elements: `"<key>" elements must be <type>, but got <actual>`
- Null/empty: `"<key>" must not be empty` (mapping/sequence with null value), `"<key>" element must not be empty` (null sequence element)
- Dependency: `"<key>" must be used with "<other>"` (property presence dependency)
- Uniqueness: `step id "<id>" must be unique` (duplicate identifier within a scope)
- Invalid reference: `job "<id>" needs nonexistent job "<ref>"` (cross-property reference)
- Cycle: `jobs must not have circular dependencies: a -> b -> a`
- Expression in static position: `"<key>" must not contain expressions`
- Expression syntax error: `invalid expression syntax: <parser message>`

**Tone:** Use `must` for all messages. Required rules enforce structural correctness; lint rules enforce security policy that the user opted into by running ghasec. `should` is too weak for either.

## Manual Maintenance Required

Most hand-written checks in `extensions.go` / `invalid_action.go` either auto-follow SchemaStore updates via `go generate` or produce build errors when schema structure changes. The one exception:

- **Filter negation check (`checkFilterNegationPatterns` in `extensions.go`):** The `targetEvents` and `filterKeys` lists are hardcoded. If GitHub adds filter support to a new event, ghasec will silently skip it — no error, no warning. Check the [GitHub Actions documentation](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions) when updating the SchemaStore submodule.
