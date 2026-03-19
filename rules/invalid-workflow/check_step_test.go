package invalidworkflow_test

import (
	"testing"

	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_StepMissingUsesAndRun(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: no action\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "is required")
	assert.Contains(t, errs[0].Message, "uses")
	assert.Contains(t, errs[0].Message, "run")
}

func TestRule_StepHasBothUsesAndRun(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@abc123\n        run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mutually exclusive")
	assert.Contains(t, errs[0].Message, "uses")
	assert.Contains(t, errs[0].Message, "run")
}

func TestRule_StepUnknownKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        unknown: value\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "unknown")
}

func TestRule_StepNotMapping(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - not a mapping\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "step")
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestRule_ValidStepKeys(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"uses step", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - id: checkout\n        name: Checkout\n        uses: actions/checkout@abc123\n        with:\n          ref: main\n        env:\n          FOO: bar\n        if: success()\n        continue-on-error: true\n        timeout-minutes: 10\n"},
		{"run step", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - id: build\n        name: Build\n        run: echo hi\n        shell: bash\n        working-directory: src\n        env:\n          FOO: bar\n        if: success()\n        continue-on-error: true\n        timeout-minutes: 10\n"},
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
