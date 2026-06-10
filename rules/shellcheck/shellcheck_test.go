package shellcheck

import (
	"context"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRunner returns preset comments and records invocations.
type mockRunner struct {
	available  bool
	comments   []Comment
	calls      int
	lastShell  string
	lastScript string
}

func (m *mockRunner) Available() bool { return m.available }
func (m *mockRunner) RunBatch(_ context.Context, shell string, scripts []string) ([][]Comment, error) {
	m.calls++
	m.lastShell = shell
	if len(scripts) > 0 {
		m.lastScript = scripts[len(scripts)-1]
	}
	out := make([][]Comment, len(scripts))
	for i := range scripts {
		out[i] = m.comments
	}
	return out, nil
}

func parseWorkflowMapping(t *testing.T, src string) workflow.WorkflowMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func parseActionMapping(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

const blockRunWorkflow = "on: push\n" +
	"jobs:\n" +
	"  build:\n" +
	"    runs-on: ubuntu-latest\n" +
	"    steps:\n" +
	"      - run: |\n" +
	"          echo $x\n"

func TestCheckWorkflow_BasicFinding(t *testing.T) {
	runner := &mockRunner{
		available: true,
		comments: []Comment{
			{Line: 1, EndLine: 1, Column: 6, EndColumn: 8, Level: "info", Code: 2086, Message: "Double quote to prevent globbing and word splitting."},
		},
	}
	rule := &Rule{Runner: runner}
	errs := rule.CheckWorkflow(parseWorkflowMapping(t, blockRunWorkflow))

	require.Len(t, errs, 1)
	assert.Equal(t, "shellcheck/SC2086", errs[0].RuleID)
	assert.Equal(t, "https://www.shellcheck.net/wiki/SC2086", errs[0].Ref)
	assert.Contains(t, errs[0].Message, "Double quote")
	require.NotNil(t, errs[0].Token)
	assert.Equal(t, 7, errs[0].Token.Position.Line) // "echo $x" YAML line
	assert.Equal(t, "$x", errs[0].Token.Value)
	// Effective shell: unspecified + ubuntu → bash.
	assert.Equal(t, "bash", runner.lastShell)
}

func TestCheckWorkflow_DropsFindingsInsideMask(t *testing.T) {
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - run: |\n" +
		"          deploy ${{ x }}\n"
	// "deploy ${{ x }}" → "deploy ${GGGGG}"; mask occupies cols 8..15 (colEnd 16).
	runner := &mockRunner{
		available: true,
		comments: []Comment{
			// Inside the mask: must be dropped.
			{Line: 1, EndLine: 1, Column: 8, EndColumn: 16, Level: "info", Code: 2086, Message: "quote the mask"},
			// Outside the mask (the "deploy" command word): must be kept.
			{Line: 1, EndLine: 1, Column: 1, EndColumn: 7, Level: "warning", Code: 2164, Message: "real finding"},
		},
	}
	rule := &Rule{Runner: runner}
	errs := rule.CheckWorkflow(parseWorkflowMapping(t, src))

	require.Len(t, errs, 1)
	assert.Equal(t, "shellcheck/SC2164", errs[0].RuleID)
	assert.Equal(t, "real finding", errs[0].Message)
}

func TestCheckWorkflow_SkipsNonShellShell(t *testing.T) {
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - run: echo $x\n" +
		"        shell: pwsh\n"
	runner := &mockRunner{available: true, comments: []Comment{{Line: 1, Column: 1, EndColumn: 2, Code: 2086, Level: "info", Message: "x"}}}
	rule := &Rule{Runner: runner}
	errs := rule.CheckWorkflow(parseWorkflowMapping(t, src))

	assert.Empty(t, errs)
	assert.Equal(t, 0, runner.calls, "shellcheck must not run for pwsh")
}

func TestCheckWorkflow_WindowsOnlySkipped(t *testing.T) {
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: windows-latest\n" +
		"    steps:\n" +
		"      - run: echo $x\n"
	runner := &mockRunner{available: true, comments: []Comment{{Line: 1, Column: 1, EndColumn: 2, Code: 2086, Level: "info", Message: "x"}}}
	rule := &Rule{Runner: runner}
	errs := rule.CheckWorkflow(parseWorkflowMapping(t, src))
	assert.Empty(t, errs)
	assert.Equal(t, 0, runner.calls)
}

func TestCheckWorkflow_UnavailableSetsHintFlag(t *testing.T) {
	runner := &mockRunner{available: false}
	rule := &Rule{Runner: runner}
	errs := rule.CheckWorkflow(parseWorkflowMapping(t, blockRunWorkflow))
	assert.Empty(t, errs)
	assert.True(t, rule.SawEligibleStep(), "eligible shell run step seen while binary unavailable")
}

func TestCheckWorkflow_UnavailableNoEligibleStep(t *testing.T) {
	// pwsh step is not eligible, so no hint flag even when binary is missing.
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - run: echo $x\n" +
		"        shell: pwsh\n"
	runner := &mockRunner{available: false}
	rule := &Rule{Runner: runner}
	_ = rule.CheckWorkflow(parseWorkflowMapping(t, src))
	assert.False(t, rule.SawEligibleStep())
}

func TestCheckWorkflow_JobDefaultsShell(t *testing.T) {
	// job defaults.run.shell: sh applies to a step without its own shell.
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    defaults:\n" +
		"      run:\n" +
		"        shell: sh\n" +
		"    steps:\n" +
		"      - run: echo $x\n"
	runner := &mockRunner{available: true}
	rule := &Rule{Runner: runner}
	_ = rule.CheckWorkflow(parseWorkflowMapping(t, src))
	assert.Equal(t, 1, runner.calls)
	assert.Equal(t, "sh", runner.lastShell)
}

const compositeAction = "name: my-action\n" +
	"runs:\n" +
	"  using: composite\n" +
	"  steps:\n" +
	"    - run: echo $x\n" +
	"      shell: bash\n"

func TestCheckAction_CompositeFinding(t *testing.T) {
	runner := &mockRunner{
		available: true,
		comments:  []Comment{{Line: 1, EndLine: 1, Column: 6, EndColumn: 8, Level: "info", Code: 2086, Message: "quote"}},
	}
	rule := &Rule{Runner: runner}
	errs := rule.CheckAction(parseActionMapping(t, compositeAction))
	require.Len(t, errs, 1)
	assert.Equal(t, "shellcheck/SC2086", errs[0].RuleID)
	assert.Equal(t, "bash", runner.lastShell)
}

func TestCheckAction_SkipsPwshAndUnspecified(t *testing.T) {
	// pwsh shell skipped.
	pwsh := "name: a\nruns:\n  using: composite\n  steps:\n    - run: echo $x\n      shell: pwsh\n"
	runner := &mockRunner{available: true, comments: []Comment{{Line: 1, Column: 1, EndColumn: 2, Code: 2086, Level: "info", Message: "x"}}}
	rule := &Rule{Runner: runner}
	assert.Empty(t, rule.CheckAction(parseActionMapping(t, pwsh)))
	assert.Equal(t, 0, runner.calls)

	// Unspecified shell skipped (no bash fallback for composite actions).
	noShell := "name: a\nruns:\n  using: composite\n  steps:\n    - run: echo $x\n"
	runner2 := &mockRunner{available: true, comments: []Comment{{Line: 1, Column: 1, EndColumn: 2, Code: 2086, Level: "info", Message: "x"}}}
	rule2 := &Rule{Runner: runner2}
	assert.Empty(t, rule2.CheckAction(parseActionMapping(t, noShell)))
	assert.Equal(t, 0, runner2.calls)
}

func TestCheckWorkflow_StyleLevelDropped(t *testing.T) {
	runner := &mockRunner{
		available: true,
		comments: []Comment{
			{Line: 1, EndLine: 1, Column: 6, EndColumn: 8, Level: "style", Code: 2006, Message: "style nit"},
		},
	}
	rule := &Rule{Runner: runner}
	errs := rule.CheckWorkflow(parseWorkflowMapping(t, blockRunWorkflow))
	assert.Empty(t, errs)
}
