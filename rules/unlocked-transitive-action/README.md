# unlocked-transitive-action

Checks that actions used inside locked actions are recorded in the [dependency lockfile](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles) (`.github/workflows/actions.lock`).

For a workflow listed in the lockfile, it reads each remote action a step uses at the commit the lockfile records, and checks the actions used inside it, recursively. Remote actions used inside composite actions of the same repository are not read.

## Risk

GitHub resolves an action used inside a locked action from that action's entry in the lockfile or from the workflow's list, and fails the job when neither records it.

## Examples

**Bad** :x:

```yaml
# .github/workflows/actions.lock records owner/action-a@v1 for this workflow,
# but not owner/action-b@v2, which owner/action-a uses internally.
steps:
  - uses: owner/action-a@v1
```

**Good** :white_check_mark:

```yaml
# .github/workflows/actions.lock records owner/action-a@v1 and owner/action-b@v2,
# and lists owner/action-b@v2 in the entry for owner/action-a@v1.
steps:
  - uses: owner/action-a@v1
```

Run `gh actions-lock` to update the lockfile.
