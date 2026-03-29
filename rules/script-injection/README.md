# script-injection

Checks that `run:` steps and `actions/github-script`'s `script:` input do not contain `${{ }}` expressions.

## Risk

When `${{ }}` expressions are interpolated directly into shell scripts or JavaScript code, an attacker who controls the expression value (e.g., a pull request title, issue body, or commit message) can inject arbitrary commands. This is known as a script injection attack.

## Examples

**Bad** :x:

```yaml
steps:
  - run: echo "${{ github.event.issue.title }}"
```

```yaml
steps:
  - uses: actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8.0.0
    with:
      script: |
        const title = '${{ github.event.issue.title }}';
```

**Good** :white_check_mark:

```yaml
steps:
  - run: echo "$TITLE"
    env:
      TITLE: ${{ github.event.issue.title }}
```

```yaml
steps:
  - uses: actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8.0.0
    with:
      script: |
        const title = process.env.TITLE;
    env:
      TITLE: ${{ github.event.issue.title }}
```

Passing values through environment variables prevents the expression from being parsed as code. The shell or JavaScript runtime treats the variable as a data value, not executable syntax.
