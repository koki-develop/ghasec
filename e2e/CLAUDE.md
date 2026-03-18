# E2E Tests

Builds the ghasec binary once in `TestMain`, then runs each `testdata/` subdirectory as a parallel test case. Test data is embedded via `go:embed`. No Go code changes needed to add or modify test cases.

## Directory Structure

```
e2e/testdata/
  <rule-id>/              # One directory per rule
    workflows/            # Multiple workflow YAML files (one per case)
    expected.yml          # Combined expected output for all cases
  <cross-cutting-case>/   # Standalone directories for non-rule-specific tests
    workflows/
    expected.yml
```

Rule-specific directories group all test cases for a single rule. Cross-cutting directories (e.g., `valid-workflow`, `multiple-files`) test general behavior.

## Adding a Test Case

**To an existing rule:** Add a new `.yml` file under `testdata/<rule-id>/workflows/` and update `expected.yml` to include the expected errors for the new file.

**For a new rule or cross-cutting test:** Create a new directory under `testdata/` with `workflows/` and `expected.yml`.

## expected.yml Format

```yaml
exit_code: 1        # 0 = no errors, 1 = errors found
stdout: ""
stderr: |
  --> {{.Dir}}/filename.yml:7:15
  ...
  7 |       - uses: actions/checkout@v6
    |               ^^^^^^^^^^^^^^^^^^^ error message (rule-id)
  ...
    Ref: https://github.com/koki-develop/ghasec/blob/main/rules/rule-id/README.md

  N error(s) found in M file(s)
```

- `{{.Dir}}` is a Go template variable replaced with the temp directory path at test time.
- The test runner sorts workflow files alphabetically before passing them to ghasec. Errors in `expected.yml` must follow that alphabetical file order.
- The test runner sets `NO_COLOR=` to disable ANSI codes. All expected output is plain text.
- Valid workflow files (no errors) produce no output entries.
- The summary line counts only files that had errors, not total files processed.
