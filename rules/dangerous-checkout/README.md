# dangerous-checkout

Checks that `actions/checkout` in `pull_request_target` or `workflow_run` workflows does not check out pull request head code.

## Risk

`pull_request_target` and `workflow_run` workflows run with access to repository secrets. Checking out fork pull request code in such a workflow lets attacker-controlled code execute with those secrets — a "pwn request" vulnerability.

## Examples

**Bad** :x:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
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
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.ref }}
```

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: ${{ github.head_ref }}
```

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
```

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: refs/pull/${{ github.event.number }}/merge
```

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: ${{ github.event.pull_request.merge_commit_sha }}
```

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          allow-unsafe-pr-checkout: true
```

```yaml
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          allow-unsafe-pr-checkout: true
```

```yaml
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
```

```yaml
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: refs/pull/${{ github.event.workflow_run.pull_requests[0].number }}/merge
```

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
```

```yaml
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          repository: ${{ github.event.workflow_run.head_repository.full_name }}
```

**Good** :white_check_mark:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Omitting the `ref:` and `repository:` parameters causes `actions/checkout` to check out the base branch of the base repository, which is safe because it is controlled by the repository maintainers. Leaving `allow-unsafe-pr-checkout` at its default (`false`) keeps the built-in protection against fork pull request checkouts active.
