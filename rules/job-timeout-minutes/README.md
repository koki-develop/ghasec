# job-timeout-minutes

Checks that every job explicitly sets `timeout-minutes`.

## Risk

GitHub Actions jobs default to a 360-minute (6-hour) timeout. If a job hangs — due to a deadlock, a stuck network call, or an infinite loop — it silently consumes runner minutes until the default timeout expires. This wastes CI budget and delays feedback. Requiring an explicit `timeout-minutes` forces authors to choose a reasonable limit for each job.

## Examples

**Bad** :x:

```yaml
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```

**Good** :white_check_mark:

```yaml
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - run: make build
```

Setting an explicit `timeout-minutes` ensures hung jobs are killed promptly, saving runner minutes and providing faster feedback when something goes wrong.
