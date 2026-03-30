# archived-action

Checks that third-party action references do not point to archived GitHub repositories.

## Risk

Archived repositories no longer receive security patches, bug fixes, or dependency updates. Using an archived action exposes workflows to known and future vulnerabilities that will never be addressed. An archived repository may also indicate that the maintainer has abandoned the project, leaving no one to respond to security advisories or breaking changes in the GitHub Actions runtime.

## Examples

**Bad** :x:

```yaml
steps:
  # This action's repository has been archived by the owner.
  - uses: <owner>/deprecated-action@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 # v2
```

**Good** :white_check_mark:

```yaml
steps:
  # Use an actively maintained alternative.
  - uses: <owner>/maintained-action@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 # v3
```

Migrate to an actively maintained alternative action that provides the same functionality.
