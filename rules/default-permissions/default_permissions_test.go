package defaultpermissions_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	defaultpermissions "github.com/koki-develop/ghasec/rules/default-permissions"
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
	r := &defaultpermissions.Rule{}
	assert.Equal(t, "default-permissions", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &defaultpermissions.Rule{}
	assert.False(t, r.Required())
}

func TestRule_PermissionsEmptyMapping(t *testing.T) {
	r := &defaultpermissions.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	assert.Empty(t, errs)
}

func TestRule_MissingPermissions(t *testing.T) {
	r := &defaultpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `permissions`)
}

func TestRule_MissingPermissions_TokenPointsToDocStart(t *testing.T) {
	r := &defaultpermissions.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Equal(t, 1, errs[0].Token.Position.Line)
}

func TestRule_PermissionsNonEmptyMapping(t *testing.T) {
	r := &defaultpermissions.Rule{}
	src := "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `permissions`)
}

func TestRule_PermissionsNonEmptyMapping_TokenPointsToKey(t *testing.T) {
	r := &defaultpermissions.Rule{}
	src := "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "permissions", errs[0].Token.Value)
}

func TestRule_PermissionsString(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			"read-all",
			"on: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
		},
		{
			"write-all",
			"on: push\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
		},
	}
	r := &defaultpermissions.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseYAML(t, tt.src)
			errs := r.Check(f)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Message, `permissions`)
		})
	}
}

func TestRule_PermissionsString_TokenPointsToKey(t *testing.T) {
	r := &defaultpermissions.Rule{}
	src := "on: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Equal(t, "permissions", errs[0].Token.Value)
}

func TestRule_PermissionsNull(t *testing.T) {
	r := &defaultpermissions.Rule{}
	src := "on: push\npermissions:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	f := parseYAML(t, src)
	errs := r.Check(f)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `permissions`)
}

func TestRule_EmptyDocument(t *testing.T) {
	r := &defaultpermissions.Rule{}
	f, err := yamlparser.ParseBytes([]byte(""), 0)
	require.NoError(t, err)
	errs := r.Check(f)
	assert.Empty(t, errs)
}
