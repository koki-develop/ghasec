package mismatchedshatag_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	mismatchedshatag "github.com/koki-develop/ghasec/rules/mismatched-sha-tag"
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

type mockResolver struct {
	shas map[string]string // "owner/repo@tag" -> sha
	err  error
}

func (m *mockResolver) ResolveTagSHA(ctx context.Context, owner, repo, tag string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	key := fmt.Sprintf("%s/%s@%s", owner, repo, tag)
	sha, ok := m.shas[key]
	if !ok {
		return "", fmt.Errorf("tag %q not found", tag)
	}
	return sha, nil
}

func TestRule_ID(t *testing.T) {
	r := &mismatchedshatag.Rule{}
	assert.Equal(t, "mismatched-sha-tag", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &mismatchedshatag.Rule{}
	assert.False(t, r.Required())
}

func TestRule_MatchingSHA(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			shas: map[string]string{
				"actions/checkout@v4": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_MismatchedSHA(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			shas: map[string]string{
				"actions/checkout@v4": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `references tag "v4", but the tag points to commit "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
}

func TestRule_SemverTag(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			shas: map[string]string{
				"actions/setup-go@v5.4.0": "0aaccfd150d50ccaeb58ebd88eb36e1752db003a",
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-go@0aaccfd150d50ccaeb58ebd88eb36e1752db003a # v5.4.0\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_NoComment(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_NotPinnedToSHA(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{},
	}
	tests := []struct {
		name string
		uses string
	}{
		{"tag ref", "actions/checkout@v4"},
		{"branch ref", "actions/checkout@main"},
		{"short sha", "actions/checkout@de0fac"},
		{"no ref", "actions/checkout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			m := parseMapping(t, src)
			errs := r.Check(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_LocalAndDockerActions(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{},
	}
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
			m := parseMapping(t, src)
			errs := r.Check(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_NoSteps(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{},
	}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_ResolverError(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			err: fmt.Errorf("network error"),
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "failed to resolve tag")
	assert.Contains(t, errs[0].Message, "network error")
}

func TestRule_TagNotFound(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			shas: map[string]string{},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v999\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "failed to resolve tag")
}

func TestRule_TokenPosition(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			shas: map[string]string{
				"actions/checkout@v4": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "v4", errs[0].Token.Value)
	require.Len(t, errs[0].ContextTokens, 3)
	assert.Equal(t, "jobs", errs[0].ContextTokens[0].Value)
	assert.Equal(t, "build", errs[0].ContextTokens[1].Value)
	assert.Equal(t, "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", errs[0].ContextTokens[2].Value)
}

func TestRule_MultipleSteps(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			shas: map[string]string{
				"actions/checkout@v4":   "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
				"actions/setup-go@v5":   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"actions/setup-node@v4": "cccccccccccccccccccccccccccccccccccccccc",
			},
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n      - uses: actions/setup-go@0aaccfd150d50ccaeb58ebd88eb36e1752db003a # v5\n      - uses: actions/setup-node@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "setup-go")
	assert.Contains(t, errs[1].Message, "setup-node")
}

func TestRule_NilResolver(t *testing.T) {
	r := &mismatchedshatag.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	assert.Empty(t, errs)
}
