# Rules

Rules marked as **Online** require network access (e.g., GitHub API) and are disabled by default. Use `--online` to enable them.

| Rule | Description | Online |
|------|-------------|--------|
| [invalid-workflow](./invalid-workflow/README.md) | Validates that a GitHub Actions workflow file has the required structure. | |
| [invalid-action](./invalid-action/README.md) | Validates that a GitHub Actions action metadata file has the required structure. | |
| [unpinned-action](./unpinned-action/README.md) | Checks that third-party action references are pinned to a full-length commit SHA. | |
| [checkout-persist-credentials](./checkout-persist-credentials/README.md) | Checks that `actions/checkout` is configured with `persist-credentials: false`. | |
| [dangerous-checkout](./dangerous-checkout/README.md) | Checks that `actions/checkout` in `pull_request_target` workflows does not check out pull request head code. | |
| [default-permissions](./default-permissions/README.md) | Checks that workflow-level `permissions` is set to `{}`. | |
| [job-all-permissions](./job-all-permissions/README.md) | Checks that job-level `permissions` does not use `read-all` or `write-all`. | |
| [job-timeout-minutes](./job-timeout-minutes/README.md) | Checks that every job explicitly sets `timeout-minutes`. | |
| [secrets-inherit](./secrets-inherit/README.md) | Checks that jobs do not use `secrets: inherit`. | |
| [invalid-expression](./invalid-expression/README.md) | Validates `${{ }}` expression syntax in workflow and action files. | |
| [missing-sha-ref-comment](./missing-sha-ref-comment/README.md) | Checks that actions pinned to a full-length commit SHA have an inline comment containing a valid git ref. | |
| [script-injection](./script-injection/README.md) | Checks that `run:` steps and `actions/github-script`'s `script:` input do not contain `${{ }}` expressions. | |
| [actor-bot-check](./actor-bot-check/README.md) | Checks that `if:` conditions in `pull_request` / `pull_request_target` workflows do not use `github.actor` to identify bots. | |
| [unused-ignore](./unused-ignore/README.md) | Reports unused, unknown, or invalid `ghasec-ignore` directives. | |
| [impostor-commit](./impostor-commit/README.md) | Checks that a commit SHA pinned in an action reference is reachable from a branch or tag in the referenced repository. | Yes |
| [mismatched-sha-tag](./mismatched-sha-tag/README.md) | Checks that a commit SHA pinned in an action reference matches the tag in its inline comment. | Yes |
