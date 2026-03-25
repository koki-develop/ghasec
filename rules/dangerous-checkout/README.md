# dangerous-checkout

Checks that `actions/checkout` in `pull_request_target` workflows does not check out pull request head code.

## Risk

Workflows triggered by `pull_request_target` run in the context of the base repository with access to repository secrets. If such a workflow checks out the pull request's head code via the `ref:` parameter of `actions/checkout`, an attacker can open a pull request from a fork containing malicious code that executes with access to those secrets.

## Examples

**Bad** :x:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
```

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.number }}/merge
```

**Good** :white_check_mark:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
```

Omitting the `ref:` parameter causes `actions/checkout` to check out the base branch code, which is safe because it is controlled by the repository maintainers.
