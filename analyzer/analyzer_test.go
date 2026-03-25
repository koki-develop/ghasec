package analyzer_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/progress"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockWorkflowRule struct {
	id       string
	required bool
	check    func(mapping workflow.WorkflowMapping) []*diagnostic.Error
}

func (r *mockWorkflowRule) ID() string     { return r.id }
func (r *mockWorkflowRule) Required() bool { return r.required }
func (r *mockWorkflowRule) Online() bool   { return false }
func (r *mockWorkflowRule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return r.check(mapping)
}

type mockActionRule struct {
	id       string
	required bool
	check    func(mapping workflow.ActionMapping) []*diagnostic.Error
}

func (r *mockActionRule) ID() string     { return r.id }
func (r *mockActionRule) Required() bool { return r.required }
func (r *mockActionRule) Online() bool   { return false }
func (r *mockActionRule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return r.check(mapping)
}

func parseYAML(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
}

func TestAnalyzeWorkflow_EmptyDocument(t *testing.T) {
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	a := analyzer.New(1)
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "workflow")
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestAnalyzeWorkflow_NonMappingDocument(t *testing.T) {
	f := parseYAML(t, "- item1\n- item2\n")
	a := analyzer.New(1)
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestAnalyzeWorkflow_RequiredRuleError_SkipsNonRequired(t *testing.T) {
	reqRule := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Message: "required error"}}
	}}
	lintCalled := false
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		lintCalled = true
		return []*diagnostic.Error{{Message: "lint error"}}
	}}
	a := analyzer.New(1, reqRule, lintRule)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "required error", errs[0].Message)
	assert.Equal(t, "req", errs[0].RuleID)
	assert.False(t, lintCalled)
}

func TestAnalyzeWorkflow_RequiredRulePass_RunsNonRequired(t *testing.T) {
	reqRule := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Message: "lint error"}}
	}}
	a := analyzer.New(1, reqRule, lintRule)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "lint error", errs[0].Message)
	assert.Equal(t, "lint", errs[0].RuleID)
}

func TestAnalyzeWorkflow_NoRules(t *testing.T) {
	a := analyzer.New(1)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)
	assert.Empty(t, errs)
}

func TestAnalyzeWorkflow_AllPass(t *testing.T) {
	noErr := func(mapping workflow.WorkflowMapping) []*diagnostic.Error { return nil }
	a := analyzer.New(1,
		&mockWorkflowRule{id: "req", required: true, check: noErr},
		&mockWorkflowRule{id: "lint", required: false, check: noErr},
	)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)
	assert.Empty(t, errs)
}

func TestAnalyzeAction_EmptyDocument(t *testing.T) {
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	a := analyzer.New(1)
	errs := a.AnalyzeAction(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "action")
	assert.Contains(t, errs[0].Message, "mapping")
}

// --- Ignore directive tests ---

func TestAnalyzeWorkflow_IgnoreSuppressesDiagnostic(t *testing.T) {
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{
			Token:   mapping.GetToken(),
			Message: "lint error",
		}}
	}}
	a := analyzer.New(1, lintRule)
	f := parseYAML(t, "key: value # ghasec-ignore:lint")
	errs := a.AnalyzeWorkflow(f)
	assert.Empty(t, errs)
}

func TestAnalyzeWorkflow_IgnoreDoesNotSuppressRequiredRule(t *testing.T) {
	reqRule := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{
			Token:   mapping.GetToken(),
			Message: "required error",
		}}
	}}
	a := analyzer.New(1, reqRule)
	f := parseYAML(t, "key: value # ghasec-ignore:req")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 2)
	assert.Equal(t, "required error", errs[0].Message)
	assert.Contains(t, errs[1].Message, "required rule")
	assert.Equal(t, "unused-ignore", errs[1].RuleID)
}

func TestAnalyzeWorkflow_RequiredIgnoreError_WhenRequiredRulePasses(t *testing.T) {
	reqRule := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}
	a := analyzer.New(1, reqRule)
	f := parseYAML(t, "key: value # ghasec-ignore:req")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "required rule")
	assert.Equal(t, "unused-ignore", errs[0].RuleID)
}

func TestAnalyzeWorkflow_AllRulesIgnore_SkipsRequiredSilently(t *testing.T) {
	reqRule := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{
			Token:   mapping.GetToken(),
			Message: "required error",
		}}
	}}
	a := analyzer.New(1, reqRule)
	f := parseYAML(t, "key: value # ghasec-ignore")
	errs := a.AnalyzeWorkflow(f)
	// All-rules ignore must NOT suppress required rule errors and must NOT
	// produce "required rule cannot be ignored" errors.
	require.Len(t, errs, 1)
	assert.Equal(t, "required error", errs[0].Message)
	assert.Equal(t, "req", errs[0].RuleID)
}

func TestAnalyzeWorkflow_UnusedIgnore_UnknownRule(t *testing.T) {
	a := analyzer.New(1)
	f := parseYAML(t, "key: value # ghasec-ignore:nonexistent")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `unknown rule "nonexistent"`)
	assert.Equal(t, "unused-ignore", errs[0].RuleID)
}

func TestAnalyzeWorkflow_UnusedIgnore_NotFired(t *testing.T) {
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}
	a := analyzer.New(1, lintRule)
	f := parseYAML(t, "key: value # ghasec-ignore:lint")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `unused ignore directive for "lint"`)
	assert.Equal(t, "unused-ignore", errs[0].RuleID)
}

func TestAnalyzeWorkflow_IgnoreAllRules(t *testing.T) {
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{
			Token:   mapping.GetToken(),
			Message: "lint error",
		}}
	}}
	a := analyzer.New(1, lintRule)
	f := parseYAML(t, "key: value # ghasec-ignore")
	errs := a.AnalyzeWorkflow(f)
	assert.Empty(t, errs)
}

func TestAnalyzeWorkflow_UnusedIgnoreAllRules(t *testing.T) {
	a := analyzer.New(1)
	f := parseYAML(t, "key: value # ghasec-ignore")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "unused ignore directive", errs[0].Message)
	assert.Equal(t, "unused-ignore", errs[0].RuleID)
}

func TestAnalyzeWorkflow_TopLevelMappingError_NotSuppressed(t *testing.T) {
	a := analyzer.New(1)
	f := parseYAML(t, "- item1 # ghasec-ignore")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestAnalyzeWorkflow_IgnoreMixedValidAndInvalid(t *testing.T) {
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{
			Token:   mapping.GetToken(),
			Message: "lint error",
		}}
	}}
	a := analyzer.New(1, lintRule)
	f := parseYAML(t, "key: value # ghasec-ignore:lint,nonexistent")
	errs := a.AnalyzeWorkflow(f)
	// lint error suppressed, but "nonexistent" produces unknown-rule error
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `unknown rule "nonexistent"`)
}

func TestAnalyzeAction_IgnoreSuppressesDiagnostic(t *testing.T) {
	lintRule := &mockActionRule{id: "lint", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{
			Token:   mapping.GetToken(),
			Message: "lint error",
		}}
	}}
	a := analyzer.New(1, lintRule)
	f := parseYAML(t, "key: value # ghasec-ignore:lint")
	errs := a.AnalyzeAction(f)
	assert.Empty(t, errs)
}

func TestAnalyzeAction_UnusedIgnore(t *testing.T) {
	a := analyzer.New(1)
	f := parseYAML(t, "key: value # ghasec-ignore:nonexistent")
	errs := a.AnalyzeAction(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `unknown rule "nonexistent"`)
}

func TestAnalyzeAction_RequiredRuleError_SkipsNonRequired(t *testing.T) {
	reqRule := &mockActionRule{id: "req", required: true, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Message: "required error"}}
	}}
	lintCalled := false
	lintRule := &mockActionRule{id: "lint", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		lintCalled = true
		return []*diagnostic.Error{{Message: "lint error"}}
	}}
	a := analyzer.New(1, reqRule, lintRule)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeAction(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "required error", errs[0].Message)
	assert.Equal(t, "req", errs[0].RuleID)
	assert.False(t, lintCalled)
}

func TestAnalyzeWorkflow_ParallelRuleOrdering(t *testing.T) {
	noopReq := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}
	ruleA := &mockWorkflowRule{id: "rule-a", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Token: mapping.GetToken(), Message: "error from rule-a"}}
	}}
	ruleB := &mockWorkflowRule{id: "rule-b", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Token: mapping.GetToken(), Message: "error from rule-b"}}
	}}
	ruleC := &mockWorkflowRule{id: "rule-c", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Token: mapping.GetToken(), Message: "error from rule-c"}}
	}}

	a := analyzer.New(4, noopReq, ruleA, ruleB, ruleC)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)

	require.Len(t, errs, 3)
	assert.Equal(t, "rule-a", errs[0].RuleID)
	assert.Equal(t, "rule-b", errs[1].RuleID)
	assert.Equal(t, "rule-c", errs[2].RuleID)
}

func TestAnalyzeWorkflow_SortByPositionThenRuleOrder(t *testing.T) {
	noopReq := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}
	// rule-a fires on line 3, rule-b fires on line 1 and line 3.
	// Expected order: line 1 (rule-b), line 3 (rule-a), line 3 (rule-b).
	src := "key1: val1\nkey2: val2\nkey3: val3\n"
	f := parseYAML(t, src)
	body := f.Docs[0].Body.(*ast.MappingNode)
	line1Token := body.Values[0].Key.GetToken()
	line3Token := body.Values[2].Key.GetToken()

	ruleA := &mockWorkflowRule{id: "rule-a", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Token: line3Token, Message: "error from rule-a on line 3"}}
	}}
	ruleB := &mockWorkflowRule{id: "rule-b", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{
			{Token: line1Token, Message: "error from rule-b on line 1"},
			{Token: line3Token, Message: "error from rule-b on line 3"},
		}
	}}

	a := analyzer.New(1, noopReq, ruleA, ruleB)
	errs := a.AnalyzeWorkflow(f)

	require.Len(t, errs, 3)
	// line 1: rule-b
	assert.Equal(t, "rule-b", errs[0].RuleID)
	assert.Equal(t, "error from rule-b on line 1", errs[0].Message)
	// line 3: rule-a first (registered before rule-b), then rule-b
	assert.Equal(t, "rule-a", errs[1].RuleID)
	assert.Equal(t, "error from rule-a on line 3", errs[1].Message)
	assert.Equal(t, "rule-b", errs[2].RuleID)
	assert.Equal(t, "error from rule-b on line 3", errs[2].Message)
}

func TestAnalyzeAction_ParallelRuleOrdering(t *testing.T) {
	noopReq := &mockActionRule{id: "req", required: true, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return nil
	}}
	ruleA := &mockActionRule{id: "rule-a", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Token: mapping.GetToken(), Message: "error from rule-a"}}
	}}
	ruleB := &mockActionRule{id: "rule-b", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Token: mapping.GetToken(), Message: "error from rule-b"}}
	}}
	ruleC := &mockActionRule{id: "rule-c", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Token: mapping.GetToken(), Message: "error from rule-c"}}
	}}

	a := analyzer.New(4, noopReq, ruleA, ruleB, ruleC)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeAction(f)

	require.Len(t, errs, 3)
	assert.Equal(t, "rule-a", errs[0].RuleID)
	assert.Equal(t, "rule-b", errs[1].RuleID)
	assert.Equal(t, "rule-c", errs[2].RuleID)
}

// --- Progress callback tests ---

func TestAnalyzeWorkflow_ProgressCallback_AllPass(t *testing.T) {
	reqRule := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}

	var statuses []progress.Status
	cb := func(s progress.Status) {
		statuses = append(statuses, s)
	}

	a := analyzer.New(1, reqRule, lintRule)
	a.InitProgress(2)
	a.SetProgressCallback(cb)
	f := parseYAML(t, "key: value")
	a.AnalyzeWorkflow(f)

	require.Len(t, statuses, 2)
	assert.Equal(t, 1, statuses[0].Completed)
	assert.Equal(t, 2, statuses[1].Completed)
	for _, s := range statuses {
		assert.Equal(t, 2, s.Total)
	}
}

func TestAnalyzeWorkflow_ProgressCallback_RequiredEarlyExit(t *testing.T) {
	reqRule := &mockWorkflowRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Message: "required error"}}
	}}
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}

	var statuses []progress.Status
	cb := func(s progress.Status) {
		statuses = append(statuses, s)
	}

	a := analyzer.New(1, reqRule, lintRule)
	a.InitProgress(2)
	a.SetProgressCallback(cb)
	f := parseYAML(t, "key: value")
	a.AnalyzeWorkflow(f)

	// required rule completes (1 callback) + early exit adjusts total (1 callback)
	require.Len(t, statuses, 2)
	assert.Equal(t, 1, statuses[0].Completed)
	assert.Equal(t, 2, statuses[0].Total)
	assert.Equal(t, 1, statuses[1].Completed)
	assert.Equal(t, 1, statuses[1].Total)
}

func TestAnalyzeWorkflow_ProgressCallback_NilIsNoop(t *testing.T) {
	a := analyzer.New(1, &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}})
	// No SetProgressCallback call — should not panic
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)
	assert.Empty(t, errs)
}

func TestAnalyzeAction_ProgressCallback(t *testing.T) {
	reqRule := &mockActionRule{id: "req", required: true, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return nil
	}}
	lintRule := &mockActionRule{id: "lint", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return nil
	}}

	var statuses []progress.Status
	cb := func(s progress.Status) {
		statuses = append(statuses, s)
	}

	a := analyzer.New(1, reqRule, lintRule)
	a.InitProgress(2)
	a.SetProgressCallback(cb)
	f := parseYAML(t, "key: value")
	a.AnalyzeAction(f)

	require.Len(t, statuses, 2)
	assert.Equal(t, 1, statuses[0].Completed)
	assert.Equal(t, 2, statuses[1].Completed)
}

func TestAnalyzer_RuleCounts(t *testing.T) {
	wfReq := &mockWorkflowRule{id: "wf-req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error { return nil }}
	wfLint := &mockWorkflowRule{id: "wf-lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error { return nil }}
	actReq := &mockActionRule{id: "act-req", required: true, check: func(mapping workflow.ActionMapping) []*diagnostic.Error { return nil }}
	actLint := &mockActionRule{id: "act-lint", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error { return nil }}

	a := analyzer.New(1, wfReq, wfLint, actReq, actLint)
	assert.Equal(t, 2, a.WorkflowRuleCount())
	assert.Equal(t, 2, a.ActionRuleCount())
}

func TestAnalyzer_AdjustTotal(t *testing.T) {
	var statuses []progress.Status
	cb := func(s progress.Status) {
		statuses = append(statuses, s)
	}

	a := analyzer.New(1)
	a.InitProgress(30)
	a.SetProgressCallback(cb)

	a.AdjustTotal(-10)

	require.Len(t, statuses, 1)
	assert.Equal(t, 20, statuses[0].Total)
	assert.Equal(t, 0, statuses[0].Completed)
}

func TestAnalyzeWorkflow_ProgressCallback_BadMapping(t *testing.T) {
	lintRule := &mockWorkflowRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}

	var statuses []progress.Status
	cb := func(s progress.Status) {
		statuses = append(statuses, s)
	}

	a := analyzer.New(1, lintRule)
	a.InitProgress(1)
	a.SetProgressCallback(cb)

	// Non-mapping document triggers early return from AnalyzeWorkflow
	f := parseYAML(t, "- item1\n- item2\n")
	errs := a.AnalyzeWorkflow(f)

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
	// Progress total should be adjusted down by 1 (the rule that was skipped)
	require.Len(t, statuses, 1)
	assert.Equal(t, 0, statuses[0].Total)
	assert.Equal(t, 0, statuses[0].Completed)
}

func TestAnalyzeAction_ProgressCallback_BadMapping(t *testing.T) {
	lintRule := &mockActionRule{id: "lint", required: false, check: func(mapping workflow.ActionMapping) []*diagnostic.Error {
		return nil
	}}

	var statuses []progress.Status
	cb := func(s progress.Status) {
		statuses = append(statuses, s)
	}

	a := analyzer.New(1, lintRule)
	a.InitProgress(1)
	a.SetProgressCallback(cb)

	f := parseYAML(t, "- item1\n- item2\n")
	errs := a.AnalyzeAction(f)

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
	require.Len(t, statuses, 1)
	assert.Equal(t, 0, statuses[0].Total)
}
