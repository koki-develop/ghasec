# unpinned-transitive-action

Checks that SHA-pinned remote actions do not transitively use unpinned actions or Docker images in their own `action.yml`.

## Risk

Even when your workflow pins an action to a commit SHA, that action may internally reference other actions using mutable tags or branches. A compromised transitive dependency undermines the security of your entire pinning strategy. This attack surface is invisible during code review because the vulnerable reference lives inside a remote repository, not in your workflow file.

The check is fully recursive: if action A uses pinned action B, and B uses pinned action C that has an unpinned dependency, it will be detected.

## Examples

**Bad** :x:

```yaml
steps:
  # This action is SHA-pinned, but internally uses other/action-b@v2 (unpinned).
  - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

**Good** :white_check_mark:

```yaml
steps:
  # This action and all of its transitive dependencies are SHA-pinned.
  - uses: owner/action-a@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

Replace the action with an alternative that pins all of its own transitive dependencies to full commit SHAs, or open an issue/PR on the action's repository requesting SHA pinning.
