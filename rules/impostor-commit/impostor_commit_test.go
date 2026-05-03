package impostorcommit_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	impostorcommit "github.com/koki-develop/ghasec/rules/impostor-commit"
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

type mockVerifier struct {
	results map[string]bool // "owner/repo@sha" -> reachable
	err     error
}

func (m *mockVerifier) VerifyCommit(_ context.Context, owner, repo, sha string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	key := fmt.Sprintf("%s/%s@%s", owner, repo, sha)
	return m.results[key], nil
}

func TestRule_ID(t *testing.T) {
	r := &impostorcommit.Rule{}
	assert.Equal(t, "impostor-commit", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &impostorcommit.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &impostorcommit.Rule{}
	assert.True(t, r.Online())
}

func TestRule_Reachable(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd": true,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_Impostor(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd": false,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "commit must belong to actions/checkout")
}

func TestRule_VerifierError(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{err: fmt.Errorf("network error")},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "failed to verify commit")
	assert.Contains(t, errs[0].Message, "network error")
}

func TestRule_NotPinnedToSHA(t *testing.T) {
	r := &impostorcommit.Rule{Verifier: &mockVerifier{}}
	tests := []struct {
		name string
		uses string
	}{
		{"tag ref", "actions/checkout@v4"},
		{"branch ref", "actions/checkout@main"},
		{"short sha", "actions/checkout@de0fac"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			errs := r.CheckWorkflow(parseMapping(t, src))
			assert.Empty(t, errs)
		})
	}
}

func TestRule_LocalAndDockerActions(t *testing.T) {
	r := &impostorcommit.Rule{Verifier: &mockVerifier{}}
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
			errs := r.CheckWorkflow(parseMapping(t, src))
			assert.Empty(t, errs)
		})
	}
}

func TestRule_Reusable_NonSHARefSkipped(t *testing.T) {
	r := &impostorcommit.Rule{Verifier: &mockVerifier{}}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_Reusable_Reachable(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"octo-org/reusable-repo@de0fac2e4500dabe0009e67214ff5f5447ce83dd": true,
			},
		},
	}
	src := "on: push\njobs:\n  call:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_Reusable_Impostor(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"octo-org/reusable-repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": false,
			},
		},
	}
	src := "on: push\njobs:\n  call:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "commit must belong to octo-org/reusable-repo")
}

func TestRule_Reusable_VerifierError(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{err: fmt.Errorf("network error")},
	}
	src := "on: push\njobs:\n  call:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "failed to verify commit")
	assert.Contains(t, errs[0].Message, "network error")
}

func TestRule_Reusable_NotPinned(t *testing.T) {
	r := &impostorcommit.Rule{Verifier: &mockVerifier{}}
	tests := []struct {
		name string
		uses string
	}{
		{"tag ref", "octo-org/reusable-repo/.github/workflows/ci.yml@v1"},
		{"branch ref", "octo-org/reusable-repo/.github/workflows/ci.yml@main"},
		{"short sha", "octo-org/reusable-repo/.github/workflows/ci.yml@de0fac"},
		{"39 chars", "octo-org/reusable-repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83d"},
		{"41 chars", "octo-org/reusable-repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd0"},
		{"uppercase", "octo-org/reusable-repo/.github/workflows/ci.yml@DE0FAC2E4500DABE0009E67214FF5F5447CE83DD"},
		{"mixed case", "octo-org/reusable-repo/.github/workflows/ci.yml@De0fac2e4500dabe0009e67214ff5f5447ce83dd"},
		{"non-hex", "octo-org/reusable-repo/.github/workflows/ci.yml@gggggggggggggggggggggggggggggggggggggggg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  call:\n    uses: %s\n", tt.uses)
			errs := r.CheckWorkflow(parseMapping(t, src))
			assert.Empty(t, errs)
		})
	}
}

func TestRule_Reusable_LocalSkipped(t *testing.T) {
	r := &impostorcommit.Rule{Verifier: &mockVerifier{}}
	src := "on: push\njobs:\n  call:\n    uses: ./.github/workflows/ci.yml\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_Reusable_NoOwnerRepo(t *testing.T) {
	r := &impostorcommit.Rule{Verifier: &mockVerifier{}}
	src := "on: push\njobs:\n  call:\n    uses: notapath@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_Reusable_TokenPosition(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"octo-org/reusable-repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": false,
			},
		},
	}
	src := "on: push\njobs:\n  call:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", errs[0].Token.Value)
}

func TestRule_Reusable_MultipleJobs(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"octo-org/reusable-repo@de0fac2e4500dabe0009e67214ff5f5447ce83dd": true,
				"octo-org/reusable-repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": false,
				"octo-org/reusable-repo@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": false,
			},
		},
	}
	src := "on: push\njobs:\n" +
		"  good:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n" +
		"  bad1:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"  bad2:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_Reusable_StepsAndReusableCoexist(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":       false,
				"octo-org/reusable-repo@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": false,
			},
		},
	}
	src := "on: push\njobs:\n" +
		"  call:\n    uses: octo-org/reusable-repo/.github/workflows/ci.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" +
		"  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_TokenPosition(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd": false,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Equal(t, "de0fac2e4500dabe0009e67214ff5f5447ce83dd", errs[0].Token.Value)
}

func TestRule_MultipleSteps(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd": true,
				"actions/setup-go@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": false,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n      - uses: actions/setup-go@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "actions/setup-go")
}

func TestRule_CheckAction(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd": false,
			},
		},
	}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	errs := r.CheckAction(parseActionMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "commit must belong to")
}

func TestRule_CheckAction_NonComposite(t *testing.T) {
	r := &impostorcommit.Rule{Verifier: &mockVerifier{}}
	src := "name: My Action\nruns:\n  using: node20\n  main: index.js\n"
	errs := r.CheckAction(parseActionMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_SubdirAction(t *testing.T) {
	r := &impostorcommit.Rule{
		Verifier: &mockVerifier{
			results: map[string]bool{
				"google-github-actions/auth@de0fac2e4500dabe0009e67214ff5f5447ce83dd": true,
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: google-github-actions/auth/cleanup@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}
