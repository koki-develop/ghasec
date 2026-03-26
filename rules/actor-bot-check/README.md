# actor-bot-check

Checks that `if:` conditions in `pull_request` / `pull_request_target` workflows do not use `github.actor` to identify bots.

## Risk

`github.actor` in pull request workflows can be manipulated. When a bot like Dependabot opens a PR, `github.actor` is set to `dependabot[bot]`. However, if someone force-pushes to the bot's branch, the actor changes to the pusher. Using `github.actor == 'dependabot[bot]'` in `if:` conditions is therefore a fragile security gate that can be bypassed.

## Examples

**Bad** :x:

```yaml
on: pull_request
jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
```

**Good** :white_check_mark:

```yaml
on: pull_request
jobs:
  auto-merge:
    runs-on: ubuntu-latest
    steps:
      - if: github.event.pull_request.user.login == 'dependabot[bot]'
        run: gh pr merge --auto
```

Use `github.event.pull_request.user.login` instead of `github.actor` for reliable bot identity verification. Unlike `github.actor`, `user.login` reflects the original PR author and cannot be changed by force-pushing to the branch.
