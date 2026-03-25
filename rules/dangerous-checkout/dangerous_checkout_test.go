package dangerouscheckout_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	dangerouscheckout "github.com/koki-develop/ghasec/rules/dangerous-checkout"
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
	r := &dangerouscheckout.Rule{}
	assert.Equal(t, "dangerous-checkout", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &dangerouscheckout.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &dangerouscheckout.Rule{}
	assert.False(t, r.Online())
}

func TestRule_Detected(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"mapping trigger + head.sha",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		},
		{
			"mapping trigger + head.ref",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n",
		},
		{
			"mapping trigger + github.head_ref",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n",
		},
		{
			"mapping trigger + pull_request.number merge ref",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n",
		},
		{
			"mapping trigger + event.number merge ref",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.number }}/merge\n",
		},
		{
			"mapping trigger + merge_commit_sha",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.merge_commit_sha }}\n",
		},
		{
			"sequence trigger",
			"on: [push, pull_request_target]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		},
		{
			"string trigger",
			"on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		},
		{
			"extra whitespace in expression",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{   github.head_ref   }}\n",
		},
		{
			"mapping trigger with multiple events",
			"on:\n  push:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		},
	}
	r := &dangerouscheckout.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckWorkflow(m)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "must not reference pull request head")
		})
	}
}

func TestRule_Detected_MultipleSteps(t *testing.T) {
	src := "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n"
	r := &dangerouscheckout.Rule{}
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
}

func TestRule_NotDetected(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"pull_request trigger",
			"on:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		},
		{
			"no ref (default checkout)",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n",
		},
		{
			"literal ref",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: main\n",
		},
		{
			"non-checkout action",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-go@v5\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		},
		{
			"no with",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
		},
		{
			"with but no ref",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n",
		},
		{
			"safe expression ref",
			"on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.sha }}\n",
		},
	}
	r := &dangerouscheckout.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_Detected_TokenPointsToRefValue(t *testing.T) {
	r := &dangerouscheckout.Rule{}
	src := "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Token.Value, "github.event.pull_request.head.sha")
}

func TestRule_Detected_ExtraContextsContainsUsesToken(t *testing.T) {
	r := &dangerouscheckout.Rule{}
	src := "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	require.Len(t, errs[0].ExtraContexts, 1)
	assert.Equal(t, "actions/checkout@v4", errs[0].ExtraContexts[0].Value)
}
