# secrets-inherit

Checks that jobs do not use `secrets: inherit`.

## Risk

`secrets: inherit` passes every secret available to the calling workflow into the reusable workflow. This violates the principle of least privilege — the called workflow gains access to secrets it may not need. If that reusable workflow is compromised, misconfigured, or contains a vulnerable action, every inherited secret is exposed, not just the ones the workflow actually requires.

Explicitly listing only the secrets a reusable workflow needs limits the blast radius of a compromise and makes the data flow between workflows auditable.

## Examples

**Bad** :x:

```yaml
on: push
permissions: {}
jobs:
  ci:
    uses: org/repo/.github/workflows/ci.yml@main
    secrets: inherit
```

**Good** :white_check_mark:

```yaml
on: push
permissions: {}
jobs:
  ci:
    uses: org/repo/.github/workflows/ci.yml@main
    secrets:
      npm-token: ${{ secrets.NPM_TOKEN }}
```

Passing only the specific secrets the reusable workflow needs ensures least-privilege access and makes secret usage explicit and auditable.
