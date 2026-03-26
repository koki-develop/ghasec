package actorbotcheck_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	actorbotcheck "github.com/koki-develop/ghasec/rules/actor-bot-check"
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

func TestRule_ID(t *testing.T) {
	r := &actorbotcheck.Rule{}
	assert.Equal(t, "actor-bot-check", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &actorbotcheck.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &actorbotcheck.Rule{}
	assert.False(t, r.Online())
}

func TestRule_Detected(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"step if: github.actor == dependabot[bot] with pull_request",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"reversed operand order",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: \"'renovate[bot]' == github.actor\"\n        run: echo hi\n",
		},
		{
			"not equal",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor != 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"compound condition",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]' && github.event_name == 'pull_request'\n        run: echo hi\n",
		},
		{
			"different bot name",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'github-actions[bot]'\n        run: echo hi\n",
		},
		{
			"job-level if",
			"on: pull_request\njobs:\n  build:\n    if: github.actor == 'dependabot[bot]'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
		},
		{
			"pull_request_target trigger",
			"on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"sequence trigger with pull_request",
			"on: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"mapping trigger with pull_request",
			"on:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"mapping trigger with multiple events",
			"on:\n  push:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"explicit expression wrapper",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: ${{ github.actor == 'dependabot[bot]' }}\n        run: echo hi\n",
		},
	}
	r := &actorbotcheck.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckWorkflow(m)
			require.Len(t, errs, 1, "expected 1 error for: %s", tt.name)
			assert.Contains(t, errs[0].Message, `must not use "github.actor" to check for bots`)
		})
	}
}

func TestRule_Detected_MultipleViolations(t *testing.T) {
	src := "on: pull_request\njobs:\n  build:\n    if: github.actor == 'dependabot[bot]'\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor != 'renovate[bot]'\n        run: echo hi\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'github-actions[bot]'\n        run: echo hi\n"
	r := &actorbotcheck.Rule{}
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 3)
}

func TestRule_NotDetected(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"push trigger",
			"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"schedule trigger",
			"on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n",
		},
		{
			"non-bot comparison",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'octocat'\n        run: echo hi\n",
		},
		{
			"no if conditions",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
		},
		{
			"empty workflow no jobs",
			"on: pull_request\njobs:\n",
		},
		{
			"unrelated expression",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.ref == 'refs/heads/main'\n        run: echo hi\n",
		},
		{
			"github.actor compared with non-string",
			"on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == true\n        run: echo hi\n",
		},
	}
	r := &actorbotcheck.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs, "expected no errors for: %s", tt.name)
		})
	}
}

func TestRule_Detected_TokenPointsToGithubActor(t *testing.T) {
	r := &actorbotcheck.Rule{}
	src := "on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "github.actor", errs[0].Token.Value)
}

func TestRule_Detected_MessageContainsTriggerPullRequest(t *testing.T) {
	r := &actorbotcheck.Rule{}
	src := "on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"pull_request"`)
}

func TestRule_Detected_MessageContainsTriggerPullRequestTarget(t *testing.T) {
	r := &actorbotcheck.Rule{}
	src := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.actor == 'dependabot[bot]'\n        run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"pull_request_target"`)
}

func TestRule_Detected_ExplicitExpressionTokenPointsToGithubActor(t *testing.T) {
	r := &actorbotcheck.Rule{}
	src := "on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - if: ${{ github.actor == 'dependabot[bot]' }}\n        run: echo hi\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "github.actor", errs[0].Token.Value)
}
