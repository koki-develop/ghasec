package shapin_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/rules/shapin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseYAML(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
}

func TestRule_ID(t *testing.T) {
	r := &shapin.Rule{}
	assert.Equal(t, "sha-pinning", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &shapin.Rule{}
	assert.False(t, r.Required())
}

func TestRule_PinnedToFullSHA(t *testing.T) {
	r := &shapin.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
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
		{"no ref", "actions/checkout"},
	}
	r := &shapin.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: %s\n", tt.uses)
			f := parseYAML(t, src)
			errs := r.Check(f)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "pinned to a full length commit SHA")
		})
	}
}

func TestRule_LocalAndDockerActions(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{"local action", "./path/to/action"},
		{"docker action", "docker://alpine:3.8"},
	}
	r := &shapin.Rule{}
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
	r := &shapin.Rule{}
	f := parseYAML(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_EmptyDocument(t *testing.T) {
	r := &shapin.Rule{}
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	errs := r.Check(f)
	assert.Empty(t, errs)
}
