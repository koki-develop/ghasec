# impostor-commit

Checks that a commit SHA pinned in an action reference is reachable from a branch or tag in the referenced repository.

## Risk

GitHub shares object storage across forks. An attacker can create a malicious commit in a fork of a popular action and reference it using the original repository's namespace (e.g., `actions/checkout@<fork-commit-sha>`). The SHA resolves successfully, but the executed code was never part of the original repository's history. This is known as an "impostor commit" attack.

Because the `uses` line looks identical to a legitimate SHA-pinned reference, this attack is difficult to detect during code review.

## Examples

**Bad** :x:

```yaml
steps:
  # This SHA exists only in a fork — it was never merged into actions/checkout.
  - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

**Good** :white_check_mark:

```yaml
steps:
  # This SHA belongs to the v4 tag on the actions/checkout repository.
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Pin to a commit SHA that is reachable from a branch or tag in the action's repository. This rule verifies reachability via the GitHub API.
