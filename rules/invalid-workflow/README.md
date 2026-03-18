# invalid-workflow

Validates that a GitHub Actions workflow file has the required structure.

This is a **required** rule — if it fails, all other rules are skipped.

## Checks

- `on` key must exist and be a string, sequence, or mapping
- `jobs` key must exist, be non-empty, and be a mapping
- Each job must have either `runs-on` or `uses`, but not both
- A job with `uses` (reusable workflow) cannot also have `steps`
- `runs-on` must be a string, sequence, or mapping
- `steps` must be a sequence
- `uses` (reusable workflow) must be a string

## Examples

**Bad** :x:

```yaml
# Missing "on"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Job has both "runs-on" and "uses"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    uses: org/repo/.github/workflows/ci.yml@main
```

```yaml
# Job has both "uses" and "steps"
on: push
jobs:
  build:
    uses: org/repo/.github/workflows/ci.yml@main
    steps:
      - run: echo hi
```

**Good** :white_check_mark:

```yaml
# Standard job with runs-on and steps
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Reusable workflow job
on: push
jobs:
  call:
    uses: org/repo/.github/workflows/ci.yml@main
```
