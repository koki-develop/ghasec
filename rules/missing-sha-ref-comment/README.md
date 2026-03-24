# missing-sha-ref-comment

Checks that actions pinned to a full-length commit SHA have an inline comment containing a valid git ref.

## Risk

A 40-character hexadecimal SHA is opaque to human reviewers. Without an inline comment indicating which tag or branch it corresponds to, reviewers cannot tell at a glance whether the pinned version is current, outdated, or suspicious. This slows down code review and increases the chance that a stale or incorrect pin goes unnoticed.

## Examples

**Bad** :x:

```yaml
steps:
  # No comment — reviewer cannot tell which version this is.
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd

  # Empty comment — same problem.
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #

  # Not a valid ref — does not identify the version.
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # this is checkout
```

**Good** :white_check_mark:

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Add the corresponding tag or branch as an inline comment so reviewers can immediately identify the version.
