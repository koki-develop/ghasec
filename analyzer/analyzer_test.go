package analyzer_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseYAML(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
}

func TestAnalyze_ValidWorkflow(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := analyzer.Analyze(f)
	assert.Empty(t, errs)
}

func TestAnalyze_MissingOn(t *testing.T) {
	f := parseYAML(t, "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "on")
}

func TestAnalyze_InvalidOnType(t *testing.T) {
	f := parseYAML(t, "on: 123\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "on")
}

func TestAnalyze_MissingJobs(t *testing.T) {
	f := parseYAML(t, "on: push\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestAnalyze_EmptyJobs(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestAnalyze_InvalidJobsType(t *testing.T) {
	f := parseYAML(t, "on: push\njobs: hello\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "jobs")
}

func TestAnalyze_ValidOnTypes(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"string", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"sequence", "on: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"mapping", "on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseYAML(t, tt.src)
			errs := analyzer.Analyze(f)
			assert.Empty(t, errs)
		})
	}
}

func TestAnalyze_JobMissingRunsOnAndUses(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "uses")
}

func TestAnalyze_JobHasBothRunsOnAndUses(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "uses")
}

func TestAnalyze_JobHasBothUsesAndSteps(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  build:\n    uses: org/repo/.github/workflows/ci.yml@main\n    steps:\n      - run: echo hi\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
	assert.Contains(t, errs[0].Message, "steps")
}

func TestAnalyze_ValidReusableWorkflowJob(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := analyzer.Analyze(f)
	assert.Empty(t, errs)
}

func TestAnalyze_InvalidRunsOnType(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: 123\n    steps:\n      - run: echo hi\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
}

func TestAnalyze_ValidRunsOnTypes(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"string", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"sequence", "on: push\njobs:\n  build:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: echo hi\n"},
		{"mapping", "on: push\njobs:\n  build:\n    runs-on:\n      group: my-group\n    steps:\n      - run: echo hi\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseYAML(t, tt.src)
			errs := analyzer.Analyze(f)
			assert.Empty(t, errs)
		})
	}
}

func TestAnalyze_InvalidStepsType(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: not-a-sequence\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "steps")
}

func TestAnalyze_InvalidUsesType(t *testing.T) {
	f := parseYAML(t, "on: push\njobs:\n  call:\n    uses: [not, a, string]\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
}

func TestAnalyze_MultipleErrors(t *testing.T) {
	f := parseYAML(t, "name: test\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "on")
	assert.Contains(t, errs[1].Message, "jobs")
}

func TestAnalyze_MultipleJobErrors(t *testing.T) {
	src := "on: push\njobs:\n  job1:\n    steps:\n      - run: echo\n  job2:\n    runs-on: ubuntu-latest\n    uses: org/repo/.github/workflows/ci.yml@main\n"
	f := parseYAML(t, src)
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 2)
}

func TestAnalyze_StepActionPinnedToFullSHA(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n"
	f := parseYAML(t, src)
	errs := analyzer.Analyze(f)
	assert.Empty(t, errs)
}

func TestAnalyze_StepActionNotPinned(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"tag", "actions/checkout@v4"},
		{"branch", "actions/checkout@main"},
		{"short sha", "actions/checkout@abc1234"},
		{"no ref", "actions/checkout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			f := parseYAML(t, src)
			errs := analyzer.Analyze(f)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "pinned to a full length commit SHA")
		})
	}
}

func TestAnalyze_StepActionLocalAndDocker(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"local action", "./path/to/action"},
		{"docker action", "docker://alpine:3.8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			f := parseYAML(t, src)
			errs := analyzer.Analyze(f)
			assert.Empty(t, errs)
		})
	}
}

func TestAnalyze_EmptyDocument(t *testing.T) {
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	errs := analyzer.Analyze(f)
	assert.Empty(t, errs)
}

func TestAnalyze_NonMappingDocument(t *testing.T) {
	f := parseYAML(t, "- item1\n- item2\n")
	errs := analyzer.Analyze(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mapping")
}
