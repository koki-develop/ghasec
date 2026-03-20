package invalidworkflow_test

import (
	"testing"

	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_UnknownTopLevelKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\nfoo: bar\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_MultipleUnknownTopLevelKeys(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\nfoo: bar\nbaz: qux\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "foo")
	assert.Contains(t, errs[1].Message, "baz")
}

func TestRule_ConcurrencyMissingGroup(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\nconcurrency:\n  cancel-in-progress: true\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "group")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_ConcurrencyStringValid(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\nconcurrency: my-group\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_InvalidDefaults(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\ndefaults: notamap\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "defaults")
	assert.Contains(t, errs[0].Message, "must be a mapping")
}

func TestRule_InvalidDefaultsRunKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\ndefaults:\n  run:\n    unknown: value\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "\"run\"")
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "unknown")
}

func TestRule_DefaultsUnknownKeyAtDefaultsLevel(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\ndefaults:\n  run:\n    shell: bash\n  foo: bar\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "defaults")
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_ConcurrencyExpression(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\nconcurrency: ${{ github.ref }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_DefaultsRunNonMapping(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\ndefaults:\n  run: not-a-mapping\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "\"run\"")
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestRule_ValidDefaults(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\ndefaults:\n  run:\n    shell: bash\n    working-directory: src\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}
