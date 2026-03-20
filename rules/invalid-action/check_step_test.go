package invalidaction_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_StepUnknownKey(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n      unknown: value\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "unknown")
}

func TestRule_StepMissingRunAndUses(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - name: nothing\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
	assert.Contains(t, errs[0].Message, "run")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_StepBothRunAndUses(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n      uses: actions/checkout@abc123\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "mutually exclusive")
}

func TestRule_StepRunWithoutShell(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "shell")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_StepRemoteActionMissingRef(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must have a ref")
	assert.Contains(t, errs[0].Message, "actions/checkout")
}

func TestRule_StepLocalAndDockerNoRefOk(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"local action", "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: ./my-action\n"},
		{"docker action", "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine:3.8\n"},
	}
	r := newRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckAction(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_StepAllKnownKeysAccepted(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"uses step", "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - id: step1\n      name: Step 1\n      uses: actions/checkout@abc123\n      with:\n        ref: main\n      env:\n        FOO: bar\n      if: success()\n      continue-on-error: true\n      working-directory: src\n"},
		{"run step", "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - id: step1\n      name: Step 1\n      run: echo hi\n      shell: bash\n      env:\n        FOO: bar\n      if: success()\n      continue-on-error: true\n      working-directory: src\n"},
	}
	r := newRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMapping(t, tt.src)
			errs := r.CheckAction(m)
			assert.Empty(t, errs)
		})
	}
}

func TestRule_StepUsesNonString(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: 42\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses")
	assert.Contains(t, errs[0].Message, "must be a string")
}

func TestRule_StepTimeoutMinutesUnknown(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n      timeout-minutes: 10\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "timeout-minutes")
}
