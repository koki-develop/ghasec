# job-timeout-minutes

Checks that every job explicitly sets `timeout-minutes`.

## Risk

GitHub Actions jobs default to a 360-minute (6-hour) timeout. A job without an explicit timeout gives an attacker — or a compromised action — a large window to operate. On self-hosted runners, a malicious step could use the full 6 hours to exfiltrate data, mine cryptocurrency, or pivot into the internal network. Even on GitHub-hosted runners, the extended window allows for slow, low-profile data exfiltration that is harder to detect.

Beyond security, a missing timeout also wastes CI budget and delays feedback when jobs hang due to deadlocks or stuck network calls. Requiring an explicit `timeout-minutes` limits both the attack surface and the operational cost of runaway jobs.

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

Setting an explicit `timeout-minutes` limits the window available to a compromised step and ensures hung jobs are killed promptly.
