# unlocked-action

Checks that workflows listed in a [dependency lockfile](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles) (`.github/workflows/actions.lock`) use only actions the lockfile records for them.

Besides the actions a workflow's steps use, it checks the actions used inside composite actions of the same repository (`$/...` and `./...`), which it reads from the repository the lockfile is in. For `./`, that is what the runner's workspace holds when a step checks out this repository there. Workflows the lockfile does not list are not checked.

## Risk

An action a step uses that the workflow's list does not record keeps the workflow from starting, also when the list is empty. When the list is not empty, an action inside a composite action of the same repository that the list does not record fails the job.

When the list is empty or null, actions inside composite actions of the same repository run without the lockfile, at whatever their refs point to.

## Examples

**Bad** :x:

```yaml
# .github/workflows/actions.lock records only actions/checkout@v6 for this workflow.
steps:
  - uses: actions/checkout@v6
  - uses: actions/setup-go@v6 # not recorded
```

**Good** :white_check_mark:

```yaml
# .github/workflows/actions.lock records actions/checkout@v6 and actions/setup-go@v6 for this workflow.
steps:
  - uses: actions/checkout@v6
  - uses: actions/setup-go@v6
```

Run `gh actions-lock` to record the action in the lockfile.
