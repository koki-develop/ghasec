# missing-app-token-permissions

Checks that `actions/create-github-app-token` specifies at least one `permission-*` input.

## Risk

By default, `actions/create-github-app-token` generates a token with every permission the GitHub App installation has. If a downstream step is compromised, the attacker gains access to all those permissions instead of only the ones actually needed.

## Examples

**Bad** :x:

```yaml
steps:
  - uses: actions/create-github-app-token@f8d387b68d61c58ab83c6c016672934102569859 # v3.0.0
    with:
      app-id: ${{ secrets.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}
```

**Good** :white_check_mark:

```yaml
steps:
  - uses: actions/create-github-app-token@f8d387b68d61c58ab83c6c016672934102569859 # v3.0.0
    with:
      app-id: ${{ secrets.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}
      permission-contents: write
```

Explicitly listing `permission-*` inputs ensures the token follows the principle of least privilege, limiting the blast radius of a compromised step.
