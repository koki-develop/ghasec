# mismatched-sha-tag

Checks that a commit SHA pinned in an action reference matches the tag written in its inline comment.

## Risk

When an action is pinned to a commit SHA with a tag comment, the comment is the primary signal reviewers use to assess which version — and which security posture — is in use. If the SHA and tag drift apart, the comment becomes a false assertion about the code being executed.

This mismatch undermines the security value of SHA pinning. A reviewer who sees `# v6.0.2` may approve the workflow believing a vetted release is in use, while the actual SHA points to a different — potentially vulnerable or unaudited — commit. In a supply chain attack scenario, an attacker who gains write access to a workflow file could change the SHA to point to malicious code while leaving the tag comment unchanged to avoid detection during code review.

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
