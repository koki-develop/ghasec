# unpinned-reusable-workflow

Checks that reusable workflow references are pinned to a full-length commit SHA.

## Risk

Reusable workflows referenced via a job-level `uses:` are typically pinned by tag (e.g. `@v1`) or branch (e.g. `@main`). Both are mutable. An attacker who compromises the upstream repository can move a tag to point to malicious code; the next time your workflow runs, that compromised reusable workflow executes with whatever secrets your caller passes in (and `secrets: inherit` would pass all of them). This is a high-impact supply chain attack vector — much more severe than an unpinned step action, because reusable workflows often run with the caller's full secret context.

Even without malicious intent, a tag can receive breaking changes at any time, causing unexpected workflow failures.

## Examples

**Bad** :x:

```yaml
jobs:
  call:
    uses: octo-org/example-repo/.github/workflows/reusable.yml@v1     # tag — mutable
  call2:
    uses: octo-org/example-repo/.github/workflows/reusable.yml@main   # branch — mutable
  call3:
    uses: octo-org/example-repo/.github/workflows/reusable.yml@de0fac # short SHA — ambiguous
```

**Good** :white_check_mark:

```yaml
jobs:
  call:
    uses: octo-org/example-repo/.github/workflows/reusable.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v1.0.0
```

Pin reusable workflow references to the full 40-character commit SHA. Add the version or tag as a comment to keep the reference human-readable. Local reusable workflow calls (`./.github/workflows/...`) are exempt because they always resolve to the calling workflow's own commit.
