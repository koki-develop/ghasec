package checkoutpersistcredentials_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	checkoutpersistcredentials "github.com/koki-develop/ghasec/rules/checkout-persist-credentials"
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
	r := &checkoutpersistcredentials.Rule{}
	assert.Equal(t, "checkout-persist-credentials", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &checkoutpersistcredentials.Rule{}
	assert.False(t, r.Required())
}

func TestRule_PersistCredentialsFalse(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"bool false",
			"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          persist-credentials: false\n",
		},
		{
			"string false",
			"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          persist-credentials: \"false\"\n",
		},
	}
	r := &checkoutpersistcredentials.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.Check(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_MissingPersistCredentials(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"no with",
			"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n",
		},
		{
			"with but no persist-credentials",
			"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          fetch-depth: 0\n",
		},
		{
			"persist-credentials true",
			"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          persist-credentials: true\n",
		},
	}
	r := &checkoutpersistcredentials.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.Check(m)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, "persist-credentials: false")
		})
	}
}

func TestRule_PersistCredentialsTrue_TokenPointsToValue(t *testing.T) {
	r := &checkoutpersistcredentials.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          persist-credentials: true\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "true", errs[0].Token.Value)
}

func TestRule_MissingPersistCredentials_TokenPointsToUses(t *testing.T) {
	r := &checkoutpersistcredentials.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", errs[0].Token.Value)
}

func TestRule_NonCheckoutAction(t *testing.T) {
	r := &checkoutpersistcredentials.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-go@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
	m := parseMapping(t, src)
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_MixedSteps(t *testing.T) {
	r := &checkoutpersistcredentials.Rule{}
	src := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
		"on: push",
		"jobs:",
		"  build:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"        with:",
		"          persist-credentials: false",
		"      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"      - uses: actions/setup-go@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
	)
	m := parseMapping(t, src)
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "persist-credentials: false")
}

func TestRule_NoSteps(t *testing.T) {
	r := &checkoutpersistcredentials.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}
