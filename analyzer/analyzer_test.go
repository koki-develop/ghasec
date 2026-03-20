package analyzer_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/diagnostic"
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
	a := analyzer.New()
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "workflow")
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestAnalyzeWorkflow_NonMappingDocument(t *testing.T) {
	f := parseYAML(t, "- item1\n- item2\n")
	a := analyzer.New()
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
	a := analyzer.New(reqRule, lintRule)
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
	a := analyzer.New(reqRule, lintRule)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "lint error", errs[0].Message)
	assert.Equal(t, "lint", errs[0].RuleID)
}

func TestAnalyzeWorkflow_NoRules(t *testing.T) {
	a := analyzer.New()
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeWorkflow(f)
	assert.Empty(t, errs)
}

func TestAnalyzeWorkflow_AllPass(t *testing.T) {
	noErr := func(mapping workflow.WorkflowMapping) []*diagnostic.Error { return nil }
	a := analyzer.New(
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
	a := analyzer.New()
	errs := a.AnalyzeAction(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "action")
	assert.Contains(t, errs[0].Message, "mapping")
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
	a := analyzer.New(reqRule, lintRule)
	f := parseYAML(t, "key: value")
	errs := a.AnalyzeAction(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "required error", errs[0].Message)
	assert.Equal(t, "req", errs[0].RuleID)
	assert.False(t, lintCalled)
}
