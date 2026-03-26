# E2E Tests

Builds the ghasec binary once in `TestMain`, then runs each `testdata/**/*.yml` file as a parallel test case. Test data is embedded via `go:embed`. No Go code changes needed to add or modify test cases.

## File Structure

```
e2e/testdata/
  <name>.yml           # Top-level test case
  <subdir>/<name>.yml  # Test case organized in a subdirectory
```

Each `.yml` file contains inputs (workflows and/or actions) and expected outputs.

## Adding a Test Case

Create a new `.yml` file under `testdata/` (or any subdirectory). The test case name is the relative path from `testdata/` without extension (e.g., `testdata/foo/bar.yml` becomes test name `foo/bar`).

## Test Case Format

```yaml
args: --online --format github-actions  # optional extra CLI flags passed to ghasec
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

    ✗ N error(s) found in M of T file(s)
```

- `args` (optional): space-separated CLI flags passed to ghasec (e.g. `--online`, `--format markdown`). Parsed with `strings.Fields`.
- `workflows`: list of objects with `name` (filename) and `content` (workflow YAML as block scalar). Files are written to `{{.Dir}}/`.
- `actions`: list of objects with `name` (filename, e.g. `action.yml`) and `content` (action YAML as block scalar). Files are written to the temp directory root (`{{.Dir}}/`), not `.github/workflows/`.
- `expected`: exit_code, stdout, stderr.
- `{{.Dir}}` is a Go template variable replaced with the temp directory path at test time.
- The test runner sorts all file paths (workflows and actions combined) alphabetically before passing them to ghasec. Errors in `stderr` must follow that alphabetical file order.
- The test runner sets `NO_COLOR=` to disable ANSI codes. All expected output is plain text.
- Valid workflow files (no errors) produce no output entries.
- The summary line shows both the error file count and the total files processed (e.g., "1 of 3 files").
