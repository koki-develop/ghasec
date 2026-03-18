# checkout-persist-credentials

Checks that `actions/checkout` is configured with `persist-credentials: false`.

## Risk

By default, `actions/checkout` persists the `GITHUB_TOKEN` in the local git config. Subsequent steps — including third-party actions — can extract this token and use it to push code, create releases, or access other repositories the token has access to.

Setting `persist-credentials: false` removes the token from git config after checkout, limiting the blast radius of a compromised downstream step.

## Examples

**Bad** :x:

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
```

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
    with:
      persist-credentials: true
```

**Good** :white_check_mark:

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
    with:
      persist-credentials: false
```
