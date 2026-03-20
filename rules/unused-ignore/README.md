# unused-ignore

Reports issues with `ghasec-ignore` comments.

## Cases

### Unknown rule

The rule name in the ignore comment does not match any known ghasec rule.

```yaml
steps:
  - uses: actions/checkout@v6 # ghasec-ignore:typo-rule
```

### Unused directive

The ignore comment targets a rule that did not produce any diagnostic on the specified line.

```yaml
steps:
  # Action is already pinned — ignore is unnecessary
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # ghasec-ignore:unpinned-action
```

### Required rule cannot be ignored

Required rules (`invalid-workflow`, `invalid-action`) enforce structural validity and cannot be suppressed with ignore comments.

```yaml
on: push # ghasec-ignore:invalid-workflow
```

## Syntax

```yaml
# Ignore specific rules (inline)
uses: actions/checkout@v6 # ghasec-ignore:unpinned-action

# Ignore specific rules (previous line)
# ghasec-ignore:unpinned-action
uses: actions/checkout@v6

# Ignore multiple rules
uses: actions/checkout@v6 # ghasec-ignore:unpinned-action,checkout-persist-credentials

# Ignore all rules
uses: actions/checkout@v6 # ghasec-ignore
```
