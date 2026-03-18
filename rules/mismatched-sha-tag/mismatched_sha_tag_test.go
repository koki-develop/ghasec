package mismatchedshatag_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	mismatchedshatag "github.com/koki-develop/ghasec/rules/mismatched-sha-tag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseYAML(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
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
	f := parseYAML(t, src)
	errs := r.Check(f)
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
	f := parseYAML(t, src)
	errs := r.Check(f)
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
	f := parseYAML(t, src)
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_NoComment(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_InvalidGitRef(t *testing.T) {
	tests := []struct {
		name    string
		comment string
	}{
		{"contains space", "some tag"},
		{"contains tilde", "v1~1"},
		{"contains caret", "v1^2"},
		{"contains colon", "v1:2"},
		{"contains backslash", "v1\\2"},
		{"contains question mark", "v1?"},
		{"contains asterisk", "v1*"},
		{"contains open bracket", "v1[0]"},
		{"double dot", "v1..2"},
		{"at brace", "v1@{0}"},
		{"single at", "@"},
		{"ends with dot", "v1."},
		{"ends with .lock", "v1.lock"},
		{"starts with dash", "-v1"},
		{"starts with dot", ".v1"},
		{"control character", "v1\x00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &mismatchedshatag.Rule{
				Resolver: &mockResolver{
					shas: map[string]string{},
				},
			}
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # %s\n", tt.comment)
			f := parseYAML(t, src)
			errs := r.Check(f)
			assert.Empty(t, errs, "invalid git ref %q should be skipped", tt.comment)
		})
	}
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
			f := parseYAML(t, src)
			errs := r.Check(f)
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
			f := parseYAML(t, src)
			errs := r.Check(f)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_NoSteps(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{},
	}
	f := parseYAML(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_EmptyDocument(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{},
	}
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_ResolverError(t *testing.T) {
	r := &mismatchedshatag.Rule{
		Resolver: &mockResolver{
			err: fmt.Errorf("network error"),
		},
	}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
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
	f := parseYAML(t, src)
	errs := r.Check(f)
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
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "v4", errs[0].Token.Value)
	require.NotNil(t, errs[0].BeforeToken)
	assert.Equal(t, "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", errs[0].BeforeToken.Value)
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
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "setup-go")
	assert.Contains(t, errs[1].Message, "setup-node")
}

func TestRule_NilResolver(t *testing.T) {
	r := &mismatchedshatag.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_ValidGitRefPatterns(t *testing.T) {
	tests := []struct {
		name    string
		comment string
	}{
		{"simple version", "v4"},
		{"semver", "v5.4.0"},
		{"with slash", "release/v1.0"},
		{"alphanumeric", "beta1"},
		{"with hyphen", "my-tag-1.0"},
		{"with underscore", "my_tag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
			r := &mismatchedshatag.Rule{
				Resolver: &mockResolver{
					shas: map[string]string{
						fmt.Sprintf("actions/checkout@%s", tt.comment): sha,
					},
				},
			}
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@%s # %s\n", sha, tt.comment)
			f := parseYAML(t, src)
			errs := r.Check(f)
			assert.Empty(t, errs, "valid git ref %q should be checked and pass", tt.comment)
		})
	}
}
