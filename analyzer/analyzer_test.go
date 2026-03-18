package analyzer_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRule struct {
	id       string
	required bool
	check    func(file *ast.File) []*diagnostic.Error
}

func (r *mockRule) ID() string                               { return r.id }
func (r *mockRule) Required() bool                           { return r.required }
func (r *mockRule) Check(file *ast.File) []*diagnostic.Error { return r.check(file) }

func parseYAML(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
}

func TestAnalyzer_EmptyDocument(t *testing.T) {
	called := false
	r := &mockRule{id: "test", required: true, check: func(file *ast.File) []*diagnostic.Error {
		called = true
		return nil
	}}
	a := analyzer.New(r)
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	errs := a.Analyze(f)
	assert.Empty(t, errs)
	assert.True(t, called)
}

func TestAnalyzer_RequiredRuleError_SkipsNonRequired(t *testing.T) {
	reqRule := &mockRule{id: "req", required: true, check: func(file *ast.File) []*diagnostic.Error {
		return []*diagnostic.Error{{Message: "required error"}}
	}}
	lintCalled := false
	lintRule := &mockRule{id: "lint", required: false, check: func(file *ast.File) []*diagnostic.Error {
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
	reqRule := &mockRule{id: "req", required: true, check: func(file *ast.File) []*diagnostic.Error {
		return nil
	}}
	lintRule := &mockRule{id: "lint", required: false, check: func(file *ast.File) []*diagnostic.Error {
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
	noErr := func(file *ast.File) []*diagnostic.Error { return nil }
	a := analyzer.New(
		&mockRule{id: "req", required: true, check: noErr},
		&mockRule{id: "lint", required: false, check: noErr},
	)
	f := parseYAML(t, "key: value")
	errs := a.Analyze(f)
	assert.Empty(t, errs)
}
