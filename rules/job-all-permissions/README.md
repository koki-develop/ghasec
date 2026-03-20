# job-all-permissions

Checks that job-level `permissions` does not use `read-all` or `write-all`.

## Risk

Using `read-all` or `write-all` at the job level grants broad permissions to the `GITHUB_TOKEN` for that job. Even when the workflow-level `permissions` is locked down to `{}`, a single job with `permissions: write-all` can undo that protection. A compromised or malicious step within that job can then use the token to push code, modify releases, or access sensitive resources.

## Examples

**Bad** :x:

```yaml
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: read-all
    steps:
      - run: echo hi
```

```yaml
on: push
permissions: {}
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
```

**Good** :white_check_mark:

```yaml
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo hi
```

Declaring individual scopes instead of `read-all` or `write-all` ensures each job receives only the permissions it actually needs, limiting the blast radius of a compromised step.
