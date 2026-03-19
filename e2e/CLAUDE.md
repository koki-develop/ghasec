# E2E Tests

Builds the ghasec binary once in `TestMain`, then runs each `testdata/*.yml` file as a parallel test case. Test data is embedded via `go:embed`. No Go code changes needed to add or modify test cases.

## File Structure

```
e2e/testdata/
  <name>.yml    # One file per test case (rule-specific or cross-cutting)
```

Each `.yml` file contains both workflow inputs and expected outputs.

## Adding a Test Case

Create a new `.yml` file under `testdata/`. The test case name is the filename without extension.

## Test Case Format

```yaml
workflows:
  - name: filename.yml
    content: |
      on: push
      permissions: {}
      jobs:
        build:
          runs-on: ubuntu-latest
          steps:
            - uses: actions/checkout@v6

expected:
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

- `workflows`: list of objects with `name` (filename) and `content` (workflow YAML as block scalar).
- `expected`: exit_code, stdout, stderr.
- `{{.Dir}}` is a Go template variable replaced with the temp directory path at test time.
- The test runner sorts workflow files alphabetically before passing them to ghasec. Errors in `stderr` must follow that alphabetical file order.
- The test runner sets `NO_COLOR=` to disable ANSI codes. All expected output is plain text.
- Valid workflow files (no errors) produce no output entries.
- The summary line counts only files that had errors, not total files processed.
