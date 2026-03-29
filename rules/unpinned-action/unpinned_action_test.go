package unpinnedaction_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
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

func parseActionMapping(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	require.NotEmpty(t, f.Docs)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_ID(t *testing.T) {
	r := &unpinnedaction.Rule{}
	assert.Equal(t, "unpinned-action", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &unpinnedaction.Rule{}
	assert.False(t, r.Required())
}

func TestRule_PinnedToFullSHA(t *testing.T) {
	r := &unpinnedaction.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NotPinned(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"tag", "actions/checkout@v6"},
		{"branch", "actions/checkout@main"},
		{"short sha", "actions/checkout@de0fac"},
	}
	r := &unpinnedaction.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.CheckWorkflow(m)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "pinned to a full length commit SHA")
		})
	}
}

func TestRule_LocalAction(t *testing.T) {
	r := &unpinnedaction.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./local-action\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_DockerActionDigestPinned(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"tag and digest", "docker://alpine:3.8@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		{"digest only", "docker://alpine@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		{"registry with digest", "docker://ghcr.io/owner/repo:latest@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
	}
	r := &unpinnedaction.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.CheckWorkflow(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_DockerActionUnpinned(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"tag only", "docker://alpine:3.8"},
		{"no tag", "docker://alpine"},
		{"registry with tag", "docker://ghcr.io/owner/repo:latest"},
		{"registry no tag", "docker://ghcr.io/owner/repo"},
		{"short digest", "docker://alpine@sha256:abcdef"},
		{"invalid hex in digest", "docker://alpine@sha256:ZZZZZZ1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		{"uppercase hex", "docker://alpine@sha256:ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		{"truncated digest", "docker://alpine@sha256:abcdef1234567890abcdef1234567890"},
		{"digest too long", "docker://alpine@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890aa"},
	}
	r := &unpinnedaction.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.CheckWorkflow(m)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "pinned to a digest")
		})
	}
}

func TestRule_NoSteps(t *testing.T) {
	r := &unpinnedaction.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_CheckAction_NotPinned(t *testing.T) {
	r := &unpinnedaction.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v6\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "pinned to a full length commit SHA")
}

func TestRule_CheckAction_Pinned(t *testing.T) {
	r := &unpinnedaction.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_CheckAction_NonComposite(t *testing.T) {
	r := &unpinnedaction.Rule{}
	src := "name: My Action\nruns:\n  using: node20\n  main: index.js\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}
