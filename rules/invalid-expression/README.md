# invalid-expression

Validates that `${{ }}` expressions in workflow and action files have correct syntax.

This rule checks both workflow files and action files.

## Checks

### Expression syntax (`${{ }}`)
- All `${{ }}` expressions must have valid syntax (correct operators, balanced parentheses, valid function calls, etc.)
- Unterminated expressions (missing `}}`) are reported

### Bare `if` expressions
- `if:` values without `${{ }}` wrappers are parsed as bare expressions and validated
- Block scalar (`|` / `>`) bare `if` values are also validated

## Examples

**Bad** :x:

```yaml
# Syntax error in expression
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event == }}
```

```yaml
# Unterminated expression
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ hello
```

```yaml
# Bare if with syntax error
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - if: github.event ==
        run: echo test
```

```yaml
# Invalid function call in action
name: Test
description: test
runs:
  using: composite
  steps:
    - run: echo ${{ contains( }}
```

**Good** :white_check_mark:

```yaml
# Valid expressions
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.actor }}
      - run: ${{ format('hello {0}', 'world') }}
```

```yaml
# Bare if expression
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - if: github.event_name == 'push'
        run: echo push
```
