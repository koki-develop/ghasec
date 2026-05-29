# shellcheck

Runs [ShellCheck](https://www.shellcheck.net/) against the shell scripts in `run:` steps and reports its findings as ghasec diagnostics.

## Requirements

This rule needs the `shellcheck` binary on `PATH`. It is enabled by default; if `shellcheck` is not installed, the rule is skipped.

## Suppressing findings

Single-line `run:` step — use a ghasec directive:

```yaml
- run: echo $x # ghasec-ignore:shellcheck/SC2086
```

Use `# ghasec-ignore:shellcheck` to suppress all ShellCheck findings on the line.

Multi-line block (`run: |`) — use ShellCheck's own directive:

```yaml
- run: |
    # shellcheck disable=SC2086
    echo $x
```

## Examples

**Bad** :x:

```yaml
- run: echo $DEPLOY_TARGET
```

**Good** :white_check_mark:

```yaml
- run: echo "$DEPLOY_TARGET"
```
