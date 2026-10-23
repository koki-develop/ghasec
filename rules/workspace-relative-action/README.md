# workspace-relative-action

Checks that same-repository actions are referenced with the self-repository syntax (`$/...`) instead of a workspace-relative path (`./...`).

## Risk

A `./` reference does not point to your repository. It loads whatever `action.yml` is at that path in the runner's workspace when the step runs. Any earlier step that changes the workspace decides which code runs: checking out pull request code, checking out another ref or repository, restoring a cache or artifact, or writing files from a script.

This also sidesteps policy controls. GitHub Actions policies never restrict access to local actions on the runner filesystem, so a workflow can clone any repository into the workspace and run it with `uses: ./...`, even when the policy would block a reference to that repository.

In a composite action, `./` resolves against the workspace of the workflow that calls the action, not the action's own repository, so the composite action can end up running code its author never wrote.

A `$/` reference resolves to the repository of the file containing it, at the commit that is running. It needs no checkout and cannot be redirected by the contents of the workspace.

## Examples

**Bad** :x:

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
    with:
      persist-credentials: false
  - uses: ./.github/actions/build
```

**Good** :white_check_mark:

```yaml
steps:
  - uses: $/.github/actions/build
```

Replace `./` with `$/`. A `$/` reference must not include an `@{ref}` suffix, and it does not require checking out the repository first.

If the `./` path points to an action from another repository that an earlier step checked out into the workspace, `$/` does not apply. Reference that action as `{owner}/{repo}@{ref}` when possible.
