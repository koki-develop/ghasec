# unpinned-action

Checks that third-party action references are pinned to a full-length commit SHA, and Docker action references are pinned to a digest.

## Risk

Git tags and branches are mutable. An attacker who compromises an action repository can move a tag (e.g., `v6`) to point to malicious code. If your workflow references that tag, it will silently execute the compromised version on the next run — a supply chain attack.

Docker image tags are similarly mutable. A `docker://` action referencing only a tag can be silently replaced with different contents.

Even without malicious intent, a tag or branch can receive breaking changes at any time, causing unexpected workflow failures.

## Examples

**Bad** :x:

```yaml
steps:
  - uses: actions/checkout@v6     # tag — mutable
  - uses: actions/checkout@main   # branch — mutable
  - uses: actions/checkout@de0fac # short SHA — ambiguous
  - uses: docker://alpine:3.8     # tag — mutable
  - uses: docker://alpine         # no tag — mutable
```

**Good** :white_check_mark:

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
  - uses: docker://alpine:3.8@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

Pin actions to the full 40-character commit SHA. Pin Docker actions to the image digest using the `@sha256:...` suffix. Adding the version/tag as a comment or keeping it in the reference keeps it human-readable.
