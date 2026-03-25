# analyzer/CLAUDE.md

## Overview

`analyzer` package runs rules against a parsed YAML AST file and collects diagnostics. It is the core orchestration layer between parsing and output.

## Execution Model

1. Extract the top-level `*ast.MappingNode` from `*ast.File`. If the document is empty or not a mapping, return an error immediately.
2. Run **required** rules first (sequentially). If any produce errors, skip all non-required rules and return.
3. Run **non-required** rules concurrently (bounded by `concurrency` parameter). Results are collected per-rule to preserve stable ordering.
4. Apply ignore directive filtering, generate unused-ignore diagnostics, and sort all results by position (line, then column).

## Ignore Directive Handling

The analyzer centralizes all `# ghasec-ignore` directive processing — individual rules do not handle ignore directives.

- Directives are collected by walking the token chain from the beginning of the file (`ignore.Collect`).
- Non-required rule diagnostics are filtered against directives by matching line position and rule ID.
- Required rules cannot be ignored. Explicitly targeting a required rule by name produces an `unused-ignore` diagnostic with `"<id>" is a required rule and cannot be ignored`. All-rules directives (no rule IDs) silently skip required rules.
- Unused directives and unknown rule IDs produce `unused-ignore` diagnostics.
- `unused-ignore` is not a real `Rule` implementation — the analyzer sets it as a `RuleID` string directly.

## Diagnostic Sorting

Diagnostics are sorted by position (line, then column) using stable sort, so rule registration order is preserved for same-position diagnostics.

## Progress Tracking

The analyzer supports optional progress reporting via a callback. `cmd/root.go` uses this to drive the progress bar.

- `SetProgressCallback(cb ProgressCallback)` — set callback invoked on each progress update. Must be called before analysis begins.
- `InitProgress(total int)` — initialize the total expected rule executions.
- `AdjustTotal(delta int)` — adjust total (e.g., on parse failure or bad mapping, subtract skipped rules).
- Rule completion is tracked internally via `completeRule()` (called after each rule execution in `runRules`).
- `AnalyzeWorkflow`/`AnalyzeAction` call `AdjustTotal` when early-returning due to bad top-level mapping.

## Key API

- `New(concurrency int, rules ...rules.Rule) *Analyzer` — constructor. Rules are classified into `WorkflowRule` and `ActionRule` lists by interface assertion.
- `AnalyzeWorkflow(f *ast.File) []*diagnostic.Error` — run workflow rules.
- `AnalyzeAction(f *ast.File) []*diagnostic.Error` — run action rules.
- `WorkflowRuleCount() int` / `ActionRuleCount() int` — rule counts by file type (used for progress total computation).
