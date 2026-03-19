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

type mockRule struct {
	id       string
	required bool
	check    func(mapping workflow.WorkflowMapping) []*diagnostic.Error
}

func (r *mockRule) ID() string     { return r.id }
func (r *mockRule) Required() bool { return r.required }
func (r *mockRule) Online() bool   { return false }
func (r *mockRule) Check(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return r.check(mapping)
}

func parseYAML(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
}

func TestAnalyzer_EmptyDocument(t *testing.T) {
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	a := analyzer.New()
	errs := a.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestAnalyzer_NonMappingDocument(t *testing.T) {
	f := parseYAML(t, "- item1\n- item2\n")
	a := analyzer.New()
	errs := a.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestAnalyzer_RequiredRuleError_SkipsNonRequired(t *testing.T) {
	reqRule := &mockRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Message: "required error"}}
	}}
	lintCalled := false
	lintRule := &mockRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		lintCalled = true
		return []*diagnostic.Error{{Message: "lint error"}}
	}}
	a := analyzer.New(reqRule, lintRule)
	f := parseYAML(t, "key: value")
	errs := a.Analyze(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "required error", errs[0].Message)
	assert.Equal(t, "req", errs[0].RuleID)
	assert.False(t, lintCalled)
}

func TestAnalyzer_RequiredRulePass_RunsNonRequired(t *testing.T) {
	reqRule := &mockRule{id: "req", required: true, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return nil
	}}
	lintRule := &mockRule{id: "lint", required: false, check: func(mapping workflow.WorkflowMapping) []*diagnostic.Error {
		return []*diagnostic.Error{{Message: "lint error"}}
	}}
	a := analyzer.New(reqRule, lintRule)
	f := parseYAML(t, "key: value")
	errs := a.Analyze(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "lint error", errs[0].Message)
	assert.Equal(t, "lint", errs[0].RuleID)
}

func TestAnalyzer_NoRules(t *testing.T) {
	a := analyzer.New()
	f := parseYAML(t, "key: value")
	errs := a.Analyze(f)
	assert.Empty(t, errs)
}

func TestAnalyzer_AllPass(t *testing.T) {
	noErr := func(mapping workflow.WorkflowMapping) []*diagnostic.Error { return nil }
	a := analyzer.New(
		&mockRule{id: "req", required: true, check: noErr},
		&mockRule{id: "lint", required: false, check: noErr},
	)
	f := parseYAML(t, "key: value")
	errs := a.Analyze(f)
	assert.Empty(t, errs)
}
