package workflow_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/git"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseMapping(t *testing.T, src string) workflow.Mapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	require.NotEmpty(t, f.Docs)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.Mapping{MappingNode: m}
}

func parseWorkflow(t *testing.T, src string) workflow.WorkflowMapping {
	t.Helper()
	m := parseMapping(t, src)
	return workflow.WorkflowMapping{Mapping: m}
}

func TestMapping_FindKey(t *testing.T) {
	m := parseMapping(t, "foo: 1\nbar: 2")
	kv := m.FindKey("bar")
	require.NotNil(t, kv)
	assert.Equal(t, "bar", kv.Key.GetToken().Value)
}

func TestMapping_FindKey_NotFound(t *testing.T) {
	m := parseMapping(t, "foo: 1")
	kv := m.FindKey("bar")
	assert.Nil(t, kv)
}

func TestMapping_FirstToken(t *testing.T) {
	m := parseMapping(t, "key: value")
	tk := m.Values[0].Value.GetToken()
	_ = tk // ensure we have a token chain
	first := m.FirstToken()
	assert.Equal(t, 1, len(first.Value))
}

func TestWorkflowMapping_EachStep(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
  test:
    steps:
      - uses: actions/setup-go@v5`
	w := parseWorkflow(t, src)
	var count int
	w.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 3, count)
}

func TestWorkflowMapping_EachStep_NoJobs(t *testing.T) {
	w := parseWorkflow(t, "name: test")
	var count int
	w.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestWorkflowMapping_EachStep_NoSteps(t *testing.T) {
	src := `jobs:
  build:
    runs-on: ubuntu-latest`
	w := parseWorkflow(t, src)
	var count int
	w.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 0, count)
}

func parseAction(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	m := parseMapping(t, src)
	return workflow.ActionMapping{Mapping: m}
}

func TestActionMapping_EachStep_CompositeWithSteps(t *testing.T) {
	src := `name: My Action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - run: echo hello
    - uses: actions/setup-go@v5`
	a := parseAction(t, src)
	var count int
	a.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 3, count)
}

func TestActionMapping_EachStep_NonComposite(t *testing.T) {
	src := `name: My Action
runs:
  using: node20
  main: index.js`
	a := parseAction(t, src)
	var count int
	a.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestActionMapping_EachStep_RunsNotMapping(t *testing.T) {
	src := `name: My Action
runs: not-a-mapping`
	a := parseAction(t, src)
	var count int
	a.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestActionMapping_EachStep_RunsMissing(t *testing.T) {
	src := `name: My Action
description: no runs key`
	a := parseAction(t, src)
	var count int
	a.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestActionMapping_EachStep_StepsNotSequence(t *testing.T) {
	src := `name: My Action
runs:
  using: composite
  steps: not-a-sequence`
	a := parseAction(t, src)
	var count int
	a.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestStepMapping_Uses(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4`
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	var found bool
	w.EachStep(func(step workflow.StepMapping) {
		ref, found = step.Uses()
	})
	assert.True(t, found)
	assert.Equal(t, "actions/checkout@v4", ref.String())
	assert.NotNil(t, ref.Token())
}

func TestStepMapping_Uses_NoUses(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - run: echo hello`
	w := parseWorkflow(t, src)
	w.EachStep(func(step workflow.StepMapping) {
		_, found := step.Uses()
		assert.False(t, found)
	})
}

func TestMapping_FindKey_NilMapping(t *testing.T) {
	m := workflow.Mapping{}
	assert.Nil(t, m.FindKey("any"))
}

func TestMapping_FirstToken_NilMapping(t *testing.T) {
	m := workflow.Mapping{}
	assert.Nil(t, m.FirstToken())
}

func TestWorkflowMapping_EachStep_NilMapping(t *testing.T) {
	w := workflow.WorkflowMapping{}
	var count int
	w.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 0, count)
}

func TestStepMapping_With(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false`
	w := parseWorkflow(t, src)
	w.EachStep(func(step workflow.StepMapping) {
		withMapping, ok := step.With()
		assert.True(t, ok)
		kv := withMapping.FindKey("persist-credentials")
		assert.NotNil(t, kv)
	})
}

func TestStepMapping_With_NoWith(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4`
	w := parseWorkflow(t, src)
	w.EachStep(func(step workflow.StepMapping) {
		_, ok := step.With()
		assert.False(t, ok)
	})
}

func TestActionRef_String(t *testing.T) {
	ref := workflow.NewActionRef("actions/checkout@abc123", nil)
	assert.Equal(t, "actions/checkout@abc123", ref.String())
}

func TestActionRef_IsLocal(t *testing.T) {
	assert.True(t, workflow.NewActionRef("./my-action", nil).IsLocal())
	assert.False(t, workflow.NewActionRef("actions/checkout@v4", nil).IsLocal())
}

func TestActionRef_IsDocker(t *testing.T) {
	assert.True(t, workflow.NewActionRef("docker://alpine:3.8", nil).IsDocker())
	assert.False(t, workflow.NewActionRef("actions/checkout@v4", nil).IsDocker())
}

func TestActionRef_Ref(t *testing.T) {
	ref := workflow.NewActionRef("actions/checkout@abc123", nil)
	assert.Equal(t, git.Ref("abc123"), ref.Ref())
}

func TestActionRef_Ref_NoAt(t *testing.T) {
	ref := workflow.NewActionRef("actions/checkout", nil)
	assert.Equal(t, git.Ref(""), ref.Ref())
}

func TestActionRef_RefToken_WithRef(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/checkout@v6`
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	w.EachStep(func(step workflow.StepMapping) {
		ref, _ = step.Uses()
	})
	tk := ref.RefToken()
	require.NotNil(t, tk)
	assert.Equal(t, "v6", tk.Value)
	assert.Greater(t, tk.Position.Column, ref.Token().Position.Column)
}

func TestActionRef_RefToken_DoubleQuoted(t *testing.T) {
	src := "jobs:\n  build:\n    steps:\n      - uses: \"actions/checkout@v6\""
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	w.EachStep(func(step workflow.StepMapping) {
		ref, _ = step.Uses()
	})
	tk := ref.RefToken()
	require.NotNil(t, tk)
	assert.Equal(t, "v6", tk.Value)
	// Column should account for the opening quote: original column + 1 (quote) + skip
	usesToken := ref.Token()
	expectedCol := usesToken.Position.Column + 1 + len("actions/checkout@")
	assert.Equal(t, expectedCol, tk.Position.Column)
}

func TestActionRef_RefToken_SingleQuoted(t *testing.T) {
	src := "jobs:\n  build:\n    steps:\n      - uses: 'actions/checkout@v6'"
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	w.EachStep(func(step workflow.StepMapping) {
		ref, _ = step.Uses()
	})
	tk := ref.RefToken()
	require.NotNil(t, tk)
	assert.Equal(t, "v6", tk.Value)
	usesToken := ref.Token()
	expectedCol := usesToken.Position.Column + 1 + len("actions/checkout@")
	assert.Equal(t, expectedCol, tk.Position.Column)
}

func TestActionRef_RefToken_LiteralBlockKeep(t *testing.T) {
	src := "jobs:\n  call:\n    uses: |\n      org/repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	w.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		ref, _ = job.Uses()
	})
	tk := ref.RefToken()
	require.NotNil(t, tk)
	// "|" preserves the trailing newline in the value, so the ref carries it too.
	assert.Equal(t, "de0fac2e4500dabe0009e67214ff5f5447ce83dd\n", tk.Value)
	// "|" indicator on line 3, content begins on line 4 indented 6 spaces.
	// Last "@" is at byte 33 of the value, so the ref starts at byte 34.
	// Source column = 6 (indent) + 34 (offset within first content line) + 1 (1-indexed) = 41.
	assert.Equal(t, 4, tk.Position.Line)
	assert.Equal(t, 41, tk.Position.Column)
}

func TestActionRef_RefToken_LiteralBlockStrip(t *testing.T) {
	src := "jobs:\n  call:\n    uses: |-\n      org/repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	w.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		ref, _ = job.Uses()
	})
	tk := ref.RefToken()
	require.NotNil(t, tk)
	assert.Equal(t, "de0fac2e4500dabe0009e67214ff5f5447ce83dd", tk.Value)
	assert.Equal(t, 4, tk.Position.Line)
	assert.Equal(t, 41, tk.Position.Column)
}

func TestActionRef_RefToken_NoRef(t *testing.T) {
	src := `jobs:
  build:
    steps:
      - uses: actions/setup-go`
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	w.EachStep(func(step workflow.StepMapping) {
		ref, _ = step.Uses()
	})
	tk := ref.RefToken()
	assert.Equal(t, ref.Token(), tk)
}

func TestActionRef_OwnerRepo(t *testing.T) {
	ref := workflow.NewActionRef("actions/checkout@abc123", nil)
	owner, repo := ref.OwnerRepo()
	assert.Equal(t, "actions", owner)
	assert.Equal(t, "checkout", repo)
}

func TestActionRef_OwnerRepo_WithSubpath(t *testing.T) {
	ref := workflow.NewActionRef("org/repo/subpath@abc123", nil)
	owner, repo := ref.OwnerRepo()
	assert.Equal(t, "org", owner)
	assert.Equal(t, "repo", repo)
}

func TestActionRef_OwnerRepo_NoSlash(t *testing.T) {
	ref := workflow.NewActionRef("invalid", nil)
	owner, repo := ref.OwnerRepo()
	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
}

func TestActionRef_OwnerRepo_LocalAction(t *testing.T) {
	ref := workflow.NewActionRef("./my-action", nil)
	owner, repo := ref.OwnerRepo()
	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
}

func TestActionRef_OwnerRepo_DockerAction(t *testing.T) {
	ref := workflow.NewActionRef("docker://alpine:3.8", nil)
	owner, repo := ref.OwnerRepo()
	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
}

func TestWorkflowMapping_EachStep_AnchoredJob(t *testing.T) {
	src := "jobs:\n  build: &build\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo hello"
	w := parseWorkflow(t, src)
	var count int
	w.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 2, count)
}

func TestWorkflowMapping_EachStep_AnchoredSteps(t *testing.T) {
	src := "jobs:\n  build:\n    steps: &steps\n      - uses: actions/checkout@v4"
	w := parseWorkflow(t, src)
	var count int
	w.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 1, count)
}

func TestWorkflowMapping_EachStep_AnchoredStep(t *testing.T) {
	src := "jobs:\n  build:\n    steps:\n      - &step\n        uses: actions/checkout@v4"
	w := parseWorkflow(t, src)
	var count int
	w.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 1, count)
}

func TestActionMapping_EachStep_AnchoredRuns(t *testing.T) {
	src := "name: My Action\nruns: &runs\n  using: composite\n  steps:\n    - uses: actions/checkout@v4"
	a := parseAction(t, src)
	var count int
	a.EachStep(func(step workflow.StepMapping) {
		count++
	})
	assert.Equal(t, 1, count)
}

func TestStepMapping_With_Anchored(t *testing.T) {
	src := "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with: &with\n          persist-credentials: false"
	w := parseWorkflow(t, src)
	w.EachStep(func(step workflow.StepMapping) {
		withMapping, ok := step.With()
		assert.True(t, ok)
		kv := withMapping.FindKey("persist-credentials")
		assert.NotNil(t, kv)
	})
}

func TestStepMapping_Uses_Anchored(t *testing.T) {
	src := "jobs:\n  build:\n    steps:\n      - uses: &ref actions/checkout@v4"
	w := parseWorkflow(t, src)
	var ref workflow.ActionRef
	var found bool
	w.EachStep(func(step workflow.StepMapping) {
		ref, found = step.Uses()
	})
	assert.True(t, found)
	assert.Equal(t, "actions/checkout@v4", ref.String())
}

func TestJobMapping_Uses_StringValue(t *testing.T) {
	w := parseWorkflow(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@abcdef\n")
	var ref workflow.ActionRef
	var found bool
	w.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		ref, found = job.Uses()
	})
	require.True(t, found)
	assert.Equal(t, "org/repo/.github/workflows/ci.yml@abcdef", ref.String())
	assert.NotNil(t, ref.Token())
}

func TestJobMapping_Uses_NoUsesKey(t *testing.T) {
	w := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
	var found bool
	w.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		_, found = job.Uses()
	})
	assert.False(t, found)
}

func TestJobMapping_Uses_NonString(t *testing.T) {
	w := parseWorkflow(t, "on: push\njobs:\n  call:\n    uses: 123\n")
	var found bool
	w.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		_, found = job.Uses()
	})
	assert.False(t, found)
}

func TestJobMapping_Uses_AnchoredValue(t *testing.T) {
	w := parseWorkflow(t, "on: push\njobs:\n  call:\n    uses: &u org/repo/.github/workflows/ci.yml@deadbeef\n")
	var ref workflow.ActionRef
	var found bool
	w.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		ref, found = job.Uses()
	})
	require.True(t, found)
	assert.Equal(t, "org/repo/.github/workflows/ci.yml@deadbeef", ref.String())
}

func TestJobMapping_Uses_LiteralBlockScalar(t *testing.T) {
	w := parseWorkflow(t, "on: push\njobs:\n  call:\n    uses: |\n      org/repo/.github/workflows/ci.yml@v1\n")
	var ref workflow.ActionRef
	var found bool
	w.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		ref, found = job.Uses()
	})
	require.True(t, found)
	assert.Equal(t, "org/repo/.github/workflows/ci.yml@v1\n", ref.String())
}
