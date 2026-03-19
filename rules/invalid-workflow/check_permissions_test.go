package invalidworkflow_test

import (
	"testing"

	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_PermissionsInvalidType(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\npermissions: 123\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "permissions")
	assert.Contains(t, errs[0].Message, "must be a string or mapping")
}

func TestRule_PermissionsInvalidStringValue(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\npermissions: admin\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "permissions")
	assert.Contains(t, errs[0].Message, "admin")
}

func TestRule_PermissionsUnknownScope(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\npermissions:\n  unknown-scope: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "permissions")
	assert.Contains(t, errs[0].Message, "unknown scope")
	assert.Contains(t, errs[0].Message, "unknown-scope")
}

func TestRule_PermissionsInvalidLevel(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\npermissions:\n  contents: admin\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "permissions")
	assert.Contains(t, errs[0].Message, "admin")
}

func TestRule_PermissionsModelsWriteInvalid(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\npermissions:\n  models: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "models")
	assert.Contains(t, errs[0].Message, "write")
}

func TestRule_PermissionsValid(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"read-all", "on: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"write-all", "on: push\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"empty mapping", "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"valid scopes", "on: push\npermissions:\n  contents: read\n  issues: write\n  actions: none\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"models read", "on: push\npermissions:\n  models: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"expression", "on: push\npermissions: ${{ fromJSON(needs.setup.outputs.permissions) }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
	}
	r := &invalidworkflow.Rule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.Check(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_PermissionsScopeNonStringValue(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\npermissions:\n  contents:\n    - read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "contents")
	assert.Contains(t, errs[0].Message, "string level")
}

func TestRule_PermissionsScopeLevelExpression(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\npermissions:\n  contents: ${{ inputs.level }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_JobPermissionsInvalid(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: 123\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "permissions")
}
