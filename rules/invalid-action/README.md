# invalid-action

Validates that a GitHub Actions action metadata file (`action.yml`/`action.yaml`) has the required structure.

This is a **required** rule — if it fails, all other rules are skipped for that file.

## Checks

### Top-level structure
- `runs` key must exist
- Unknown top-level keys are rejected (only `name`, `description`, `author`, `inputs`, `outputs`, `runs`, `branding` are allowed)

### `runs` validation
- `runs` must be a mapping with a `using` key
- `using` must be one of: `composite`, `node12`, `node16`, `node20`, `node24`, `docker`
- Allowed keys depend on the `using` value:
  - **JS** (`node12`/`node16`/`node20`/`node24`): `using`, `main` (required), `pre`, `pre-if`, `post`, `post-if`
  - **Composite**: `using`, `steps` (required)
  - **Docker**: `using`, `image` (required), `env`, `entrypoint`, `pre-entrypoint`, `pre-if`, `post-entrypoint`, `post-if`, `args`

### Composite step validation
- Each step must have either `run`+`shell` or `uses`, but not both
- `shell` is required when `run` is present
- Remote actions (not local `./` or `docker://`) in `uses` must include a `@<ref>`
- Unknown step keys are rejected (only `run`, `shell`, `uses`, `with`, `name`, `id`, `if`, `env`, `continue-on-error`, `working-directory` are allowed)

### `inputs` validation
- Each input entry must be a mapping
- Unknown keys within an input entry are rejected (only `description`, `required`, `default`, `deprecationMessage` are allowed)

### `outputs` validation
- Each output entry must be a mapping
- For composite actions, `value` is required in each output entry
- Unknown keys within an output entry are rejected (JS/Docker: `description`; composite: `description`, `value`)

### `branding` validation
- Unknown keys are rejected (only `color`, `icon` are allowed)
- `color` must be one of: `white`, `black`, `yellow`, `blue`, `green`, `orange`, `red`, `purple`, `gray-dark`
- `icon` must be a valid Feather icon name

## Examples

**Bad** :x:

```yaml
# Missing "runs"
name: My Action
description: Does something
```

```yaml
# Unknown top-level key
runs:
  using: node20
  main: index.js
foo: bar
```

```yaml
# Unknown "using" value
runs:
  using: python3
```

```yaml
# Composite action missing "steps"
runs:
  using: composite
```

```yaml
# Composite step with "run" but no "shell"
runs:
  using: composite
  steps:
    - run: echo hi
```

```yaml
# Composite step with both "run" and "uses"
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
      uses: actions/checkout@abc123
```

```yaml
# Unknown input key
runs:
  using: node20
  main: index.js
inputs:
  token:
    foo: bar
```

```yaml
# Invalid branding color
runs:
  using: node20
  main: index.js
branding:
  color: pink
```

**Good** :white_check_mark:

```yaml
# Composite action
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
      with:
        persist-credentials: false
```

```yaml
# JS action
runs:
  using: node20
  main: index.js
  pre: setup.js
  post: cleanup.js
```

```yaml
# Docker action
runs:
  using: docker
  image: Dockerfile
  entrypoint: /entrypoint.sh
```
