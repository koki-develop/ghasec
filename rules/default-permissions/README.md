# default-permissions

Checks that the workflow-level `permissions` is set to `{}` (empty) to enforce least privilege.

## Risk

By default, GitHub Actions grants a broad set of permissions to the `GITHUB_TOKEN`. If a workflow does not explicitly restrict permissions at the top level, every job inherits these broad defaults. A compromised or malicious step can then use the token to push code, modify releases, or access sensitive resources.

Setting `permissions: {}` at the workflow level revokes all permissions by default, forcing each job to declare only the permissions it actually needs.

## Examples

**Bad** :x:

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
```

```yaml
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
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
