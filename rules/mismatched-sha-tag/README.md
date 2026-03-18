# mismatched-sha-tag

Checks that a commit SHA pinned in an action reference matches the tag written in its inline comment.

## Risk

When an action is pinned to a commit SHA with a tag comment, the comment serves as a human-readable indicator of which version is in use. If the SHA and tag drift apart — for example after updating the SHA without updating the comment, or vice versa — the comment becomes misleading. Reviewers and maintainers may believe a specific version is deployed when it is not, potentially missing security patches or introducing unexpected behavior.

## Examples

**Bad** :x:

```yaml
steps:
  # The SHA does not belong to v6.0.2 — it may be outdated or incorrect.
  - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v6.0.2
```

**Good** :white_check_mark:

```yaml
steps:
  # The SHA matches the v6.0.2 tag on the actions/checkout repository.
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Pin to the full 40-character commit SHA and add the corresponding tag as an inline comment. This rule verifies the two stay in sync.
