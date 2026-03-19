---
name: add-rule
description: |
  Add a new lint rule to ghasec — covers the full lifecycle from requirements clarification through design, implementation (TDD), E2E testing, and documentation. Use this skill whenever the user asks to add, create, or implement a new rule, lint check, or validation for GitHub Actions workflows in this project. Also trigger when the user describes a security check or best practice they want enforced on workflow files.
---

# Adding a New Rule to ghasec

This skill guides the full process of adding a new lint rule: clarifying requirements, designing, implementing with TDD, updating E2E tests, and documenting.

## Phase 1: Requirements Clarification

Before writing any code, understand what the rule should do. Ask the user these questions **one at a time**:

1. **What does the rule check?** Get a clear description of the violation it detects.
2. **Scope** — Does it apply to all steps, specific actions, specific keys? Narrow down precisely what AST nodes are relevant.
3. **Required or non-required?** Required rules (like `invalid-workflow`) validate structure and gate non-required rules. Most new rules are non-required (lint checks).
4. **Error message and position** — What message should the user see? Which token should the error point to? Consider whether different scenarios warrant different token positions (e.g., pointing to a bad value vs. a missing key).

If the user's initial request is already specific enough, skip questions you can already answer. Don't ask what you already know.

## Phase 2: Design

Propose 2-3 approaches with trade-offs and a recommendation. For most rules, following the `unpinned-action` pattern (AST traversal of jobs -> steps) is the right default. Call this out and explain why, but still offer alternatives if they exist.

Present the design concisely:
- Rule ID (kebab-case describing the violation, e.g., `unpinned-action`, `checkout-persist-credentials`)
- Package name (rule ID without hyphens, e.g., `unpinnedaction`, `checkoutpersistcredentials`)
- Detection logic (step by step)
- Error message and token position
- Required/non-required

Get user approval before proceeding.

## Phase 3: Implementation (TDD)

Follow this order strictly — tests first, then implementation.

### Step 1: Unit tests

Create `rules/<rule-id>/<rule_name>_test.go`. Follow the pattern in existing test files:

```go
package rulename_test

import (
    "testing"

    "github.com/goccy/go-yaml/ast"
    yamlparser "github.com/goccy/go-yaml/parser"
    rulename "github.com/koki-develop/ghasec/rules/<rule-id>"
    "github.com/koki-develop/ghasec/workflow"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func parseMapping(t *testing.T, src string) workflow.WorkflowMapping {
    t.Helper()
    f, err := yamlparser.ParseBytes([]byte(src), 0)
    require.NoError(t, err)
    require.NotEmpty(t, f.Docs)
    m, ok := f.Docs[0].Body.(*ast.MappingNode)
    require.True(t, ok)
    return workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
}
```

Cover at minimum:
- `ID()` returns the correct rule ID
- `Required()` returns the expected value
- Valid cases (no error expected)
- Each violation scenario (error expected, check message content)
- Non-matching cases (e.g., different action, no steps)
- Empty document / reusable workflow (no steps) — should not error
- Token position verification for each distinct error position

### Step 2: Rule implementation

Create `rules/<rule-id>/<rule_name>.go`. Follow the existing pattern:

```go
package rulename

import (
    "github.com/koki-develop/ghasec/diagnostic"
    "github.com/koki-develop/ghasec/workflow"
)

const id = "<rule-id>"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Check(mapping workflow.WorkflowMapping) []*diagnostic.Error {
    // Use mapping.FindKey(), mapping.EachStep(), step.Uses() etc.
}
```

There are two common rule patterns:

**Step-level rules** (e.g., `unpinned-action`, `checkout-persist-credentials`):
- Use `mapping.EachStep(func(step workflow.StepMapping) { ... })` to iterate steps
- Use `step.Uses()` to get an `ActionRef` — handles both `*ast.StringNode` and `*ast.LiteralNode`
- Use `ref.IsLocal()`, `ref.IsDocker()`, `ref.Ref()`, `ref.OwnerRepo()` for action classification

**Top-level rules** (e.g., `default-permissions`):
- Use `mapping.FindKey("key")` to check keys on the workflow mapping
- Use `mapping.FirstToken()` to get a file-start token for errors on missing keys

**Common patterns for both:**
- Return `nil` early for missing/unexpected nodes (required rules already validated structure)
- Use `m.FindKey()` to navigate mapping nodes (wrap raw `*ast.MappingNode` in `workflow.Mapping{MappingNode: m}` if needed)
- To point at a mapping value's key, use `kv.Key.GetToken()` — note that `MappingNode.GetToken()` returns the `:` separator, not the key

### Step 3: Run unit tests

Run `go test ./rules/<rule-id>/... -v` and verify all tests pass.

### Step 4: Register the rule

In `cmd/root.go`:
1. Add import (keep imports alphabetically ordered)
2. Add `&rulename.Rule{}` to `analyzer.New(...)`

### Step 5: Create README

Create `rules/<rule-id>/README.md` following the existing pattern:

```markdown
# <rule-id>

<One-line description>

## Risk

<Brief risk description — what can go wrong>

## Examples

**Bad** :x:

\`\`\`yaml
<violation example>
\`\`\`

**Good** :white_check_mark:

\`\`\`yaml
<correct example>
\`\`\`

<Detailed explanation — how the fix mitigates the risk>
```

## Phase 4: E2E Test Updates

See `e2e/CLAUDE.md` for the test directory structure and `expected.yml` format.

### Part A: Update existing E2E tests

1. Run `go test ./e2e/...` to see which tests fail
2. For each failing test, update its workflow to satisfy the new rule or update `expected.yml` as needed
3. When workflow files gain new lines (e.g., adding `permissions: {}`), existing `expected.yml` files may need line number updates

### Part B: Add new E2E test cases

1. Create `e2e/testdata/<rule-id>/workflows/` with violation and valid case workflows
2. Generate `expected.yml` by running: `NO_COLOR= go run . e2e/testdata/<rule-id>/workflows/*.yml 2>&1`
3. Replace the directory path with `{{.Dir}}/` in the output

## Phase 5: Documentation

Update these files:

1. **`rules/CLAUDE.md`** — Add entry to "Existing Rules" section
2. **`rules/README.md`** — Add row to the rules index table

## Phase 6: Final Verification

Run the full test suite and build:

```bash
go test ./...
go build -o ghasec .
```

All tests must pass and the binary must build successfully before considering the work complete.

## Checklist

Use this to track progress:

- [ ] Requirements clarified
- [ ] Design approved
- [ ] Unit tests written
- [ ] Rule implemented
- [ ] Unit tests passing
- [ ] Rule registered in cmd/root.go
- [ ] README created
- [ ] Existing E2E tests updated
- [ ] New E2E test cases added
- [ ] All E2E tests passing
- [ ] rules/CLAUDE.md updated
- [ ] rules/README.md updated
- [ ] Full test suite passing
- [ ] Binary builds successfully
