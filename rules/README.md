# Rules

| Rule | Description |
|------|-------------|
| [invalid-workflow](./invalid-workflow/README.md) | Validates that a GitHub Actions workflow file has the required structure. |
| [unpinned-action](./unpinned-action/README.md) | Checks that third-party action references are pinned to a full-length commit SHA. |
| [checkout-persist-credentials](./checkout-persist-credentials/README.md) | Checks that `actions/checkout` is configured with `persist-credentials: false`. |
| [default-permissions](./default-permissions/README.md) | Checks that workflow-level `permissions` is set to `{}`. |
