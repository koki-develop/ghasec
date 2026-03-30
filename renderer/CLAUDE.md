# renderer/CLAUDE.md

## Overview

`renderer` package handles diagnostic error rendering with source annotation. It reads the source file, computes ancestor breadcrumbs from token positions, and prints annotated output to stderr using `koki-develop/annotate-go`.

## Rendering Pipeline

1. Read the source file from disk.
2. Build labels: a primary label (caret marker + error message) from the diagnostic token, context labels from computed ancestors and `ExtraContexts`, and additional marker labels from `Markers`.
3. Compute the annotation using `annotate-go`, optionally with YAML syntax highlighting via `alecthomas/chroma`.
4. Print the header (`--> path:line:col`) and annotation block to stderr.

## Ancestor Breadcrumbs

`computeAncestors` walks backward through the token chain from the error token, collecting mapping keys and sequence entries at strictly decreasing indentation (column) levels. This produces the "..." context lines that show where in the YAML hierarchy the error occurred. Rules do NOT need to compute ancestors manually — the renderer does it automatically.

## Token Span Computation

`tokenSpan` converts a YAML token's position into a byte-offset span over the source. It derives byte offsets from line and column (not `Token.Offset`) to work around a goccy/go-yaml bug where comment tokens cause subsequent offsets to drift by -1 per comment. The span is clamped to a single line, guaranteed to have non-zero length, and handles quoted strings and null/empty tokens.

## Color Support (DefaultRenderer)

- `NewDefault(noColor bool)` — when `noColor` is true, all ANSI styling and syntax highlighting are disabled.
- Styling is applied via `annotate.StyleFunc` wrappers that become identity functions when color is off.
- Supports `NO_COLOR` environment variable (handled at the CLI level in `cmd/root.go`).

## Key API

- `Renderer` — interface with `PrintParseError`, `PrintDiagnosticError`, `PrintSummary`, and `PrintHint`. Used by `cmd/root.go` to abstract over output formats.
- `NewDefault(noColor bool) *DefaultRenderer` — constructor for the annotated stderr renderer (default format).
- `NewGitHubActions() *GitHubActionsRenderer` — constructor for the GitHub Actions `::error` workflow command renderer. Outputs to stdout. See `github_actions.go`.
- `NewMarkdown(ruleList []rules.Rule) *MarkdownRenderer` — constructor for the Markdown renderer. Outputs to stdout. Looks up `rules.Explainer` on each rule for optional Why/Fix guidance. Includes a `**Ref**` link to the rule's README for each diagnostic. See `markdown.go`.
- `PrintParseError(path string, err error) error` — render a YAML parse error (from `goccy/go-yaml`).
- `PrintDiagnosticError(path string, e *diagnostic.Error) error` — render a diagnostic error with source annotation, ancestor breadcrumbs, and rule reference URL.
- `PrintSummary(totalFiles, errorCount, errorFileCount, skippedOnline int) error` — render a styled summary block with file counts, error counts, and optional online-rules warning. No-op for `GitHubActionsRenderer`. `MarkdownRenderer` outputs a plain-text summary to stdout.
- `PrintHint(message string) error` — render a styled hint message. `DefaultRenderer` outputs yellow text with an info icon to stderr. `GitHubActionsRenderer` emits a `::warning` workflow command to stdout. `MarkdownRenderer` outputs a blockquote hint to stdout.
