# deprecated-commands

Detects usage of deprecated GitHub Actions workflow commands and the `ACTIONS_ALLOW_UNSECURE_COMMANDS` environment variable.

## Risk

GitHub deprecated the `::set-env`, `::add-path`, `::set-output`, and `::save-state` workflow commands in favor of environment files. The `::set-env` and `::add-path` commands have known security vulnerabilities: any process that can write to stdout can inject arbitrary environment variables or prepend entries to `PATH`, enabling code execution.

Setting `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` re-enables the disabled `::set-env` and `::add-path` commands, exposing the workflow to these injection attacks.

> [!NOTE]
> This rule detects deprecated commands in `echo`, `printf`, and `print` arguments by parsing the shell script with a bash parser. Commands output through other means (variable expansion, heredocs, other commands) are not detected.

## Examples

**Bad** :x:

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::set-env name=FOO::bar"
```

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::add-path::/usr/local/bin"
```

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::set-output name=result::value"
```

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::save-state name=pid::1234"
```

```yaml
on: push
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
```

**Good** :white_check_mark:

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "FOO=bar" >> "$GITHUB_ENV"
```

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "/usr/local/bin" >> "$GITHUB_PATH"
```

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "result=value" >> "$GITHUB_OUTPUT"
```

```yaml
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "pid=1234" >> "$GITHUB_STATE"
```

## Replacements

| Deprecated Command | Environment File |
|---|---|
| `echo "::set-env name=NAME::VALUE"` | `echo "NAME=VALUE" >> "$GITHUB_ENV"` |
| `echo "::add-path::PATH"` | `echo "PATH" >> "$GITHUB_PATH"` |
| `echo "::set-output name=NAME::VALUE"` | `echo "NAME=VALUE" >> "$GITHUB_OUTPUT"` |
| `echo "::save-state name=NAME::VALUE"` | `echo "NAME=VALUE" >> "$GITHUB_STATE"` |
