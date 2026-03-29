# unpinned-container

Checks that container images in job `container` and `services` definitions are pinned to a digest.

## Risk

Container image tags (e.g., `ubuntu:22.04`, `redis:7`) are mutable. A compromised or updated registry image can change the contents behind a tag, silently executing different code on the next workflow run. Even without malicious intent, an upstream image update can introduce breaking changes or unexpected behavior.

## Examples

**Bad** :x:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container: ubuntu:22.04 # tag — mutable
    services:
      redis:
        image: redis:7 # tag — mutable
      postgres:
        image: postgres # no tag — mutable
```

**Good** :white_check_mark:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container: ubuntu:22.04@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
    services:
      redis:
        image: redis:7@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

Pin to the image digest using the `image:tag@sha256:...` format. The tag keeps it human-readable, the digest ensures immutability.
