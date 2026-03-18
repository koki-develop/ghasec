# unpinned-action

Checks that third-party action references are pinned to a full-length commit SHA.

## Risk

Git tags and branches are mutable. An attacker who compromises an action repository can move a tag (e.g., `v6`) to point to malicious code. If your workflow references that tag, it will silently execute the compromised version on the next run — a supply chain attack.

Even without malicious intent, a tag or branch can receive breaking changes at any time, causing unexpected workflow failures.

## Examples

**Bad** :x:

```yaml
steps:
  - uses: actions/checkout@v6        # tag — mutable
  - uses: actions/checkout@main      # branch — mutable
  - uses: actions/checkout@de0fac    # short SHA — ambiguous
  - uses: actions/checkout           # no ref at all
```

**Good** :white_check_mark:

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Pin to the full 40-character commit SHA. Adding the version as a comment keeps it human-readable.
