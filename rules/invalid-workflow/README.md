# invalid-workflow

Validates that a GitHub Actions workflow file has the required structure.

This is a **required** rule — if it fails, all other rules are skipped.

## Checks

### Top-level structure
- `on` key must exist and be a string, sequence, or mapping
- `jobs` key must exist, be non-empty, and be a mapping
- Unknown top-level keys are rejected (only `name`, `run-name`, `on`, `permissions`, `env`, `defaults`, `concurrency`, `jobs` are allowed)

### Event validation (`on`)
- Unknown event names are rejected (e.g., `invalid_event`)
- Filter conflicts: an event cannot have both `branches` and `branches-ignore`, both `tags` and `tags-ignore`, or both `paths` and `paths-ignore`
- `schedule` must be a sequence, and each entry must have a `cron` key
- `workflow_dispatch` only allows the `inputs` key

### Permissions validation
- `permissions` (workflow-level and job-level) must be a string or mapping
- String values must be `read-all` or `write-all`
- Mapping keys must be known scopes (e.g., `contents`, `issues`, `actions`, etc.)
- Scope values must be `read`, `write`, or `none`

### Defaults validation
- `defaults` (workflow-level and job-level) only allows the `run` key

### Concurrency validation
- `concurrency` can be a string or mapping
- When a mapping, it must have a `group` key

### Job validation
- Each job must be a mapping
- Each job must have either `runs-on` or `uses`, but not both
- A job with `uses` (reusable workflow) cannot also have `steps`
- `runs-on` must be a string, sequence, or mapping
- `steps` must be a sequence
- `uses` (reusable workflow) must be a string
- `strategy` must have a `matrix` key
- Unknown job keys are rejected (allowed keys differ for normal jobs vs. reusable workflow jobs)

### Step validation
- Each step must have either `uses` or `run`, but not both
- Remote actions (not local `./` or `docker://`) in `uses` must include a `@<ref>`
- Unknown step keys are rejected

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
# Unknown top-level key
on: push
foo: bar
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Unknown event name
on: invalid_event
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Filter conflict: branches and branches-ignore
on:
  push:
    branches: [main]
    branches-ignore: [dev]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Invalid permissions type
on: push
permissions: 123
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Invalid permissions string value
on: push
permissions: admin
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Invalid permissions scope value
on: push
permissions:
  contents: admin
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Concurrency mapping missing "group"
on: push
concurrency:
  cancel-in-progress: true
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
# Step has both "uses" and "run"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        run: echo hi
```

```yaml
# Step missing "uses" and "run"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: missing action
```

```yaml
# Remote action missing ref
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout
```

```yaml
# Unknown job key
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    foo: bar
    steps:
      - run: echo hi
```

```yaml
# Strategy missing "matrix"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
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

```yaml
# Concurrency as a string
on: push
concurrency: my-group
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
# Empty permissions (lock down all scopes)
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```
