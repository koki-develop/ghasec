# broad-secret-env

Checks that workflow-level and job-level environment variables do not contain secrets or `github.token`.

## Risk

Setting `${{ secrets.* }}` or `${{ github.token }}` in workflow-level or job-level `env` exposes those values to every step in the scope, including third-party actions that do not need access. This violates the principle of least privilege — if any step in the scope is compromised or behaves unexpectedly, all exposed secrets are at risk.

Step-level `env` limits the secret's visibility to a single step, reducing the blast radius of a potential compromise.

## Examples

**Bad** :x:

```yaml
on: push
permissions: {}
env:
  TOKEN: ${{ secrets.DEPLOY_TOKEN }}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: deploy --token "$TOKEN"
```

```yaml
on: push
permissions: {}
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    steps:
      - run: deploy --token "$TOKEN"
```

**Good** :white_check_mark:

```yaml
on: push
permissions: {}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: deploy --token "$TOKEN"
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

Setting the secret at the step level ensures only the step that actually needs it has access.
