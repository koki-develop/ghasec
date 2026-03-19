package invalidworkflow_test

import (
	"testing"

	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_UnknownEventString(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: invalid_event\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown event")
	assert.Contains(t, errs[0].Message, "invalid_event")
}

func TestRule_UnknownEventSequence(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: [push, invalid_event]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown event")
	assert.Contains(t, errs[0].Message, "invalid_event")
}

func TestRule_UnknownEventMapping(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  invalid_event:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown event")
	assert.Contains(t, errs[0].Message, "invalid_event")
}

func TestRule_FilterConflictBranches(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  push:\n    branches: [main]\n    branches-ignore: [dev]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "branches")
	assert.Contains(t, errs[0].Message, "branches-ignore")
}

func TestRule_FilterConflictTags(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  push:\n    tags: [v1]\n    tags-ignore: [v2]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "tags")
	assert.Contains(t, errs[0].Message, "tags-ignore")
}

func TestRule_FilterConflictPaths(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  push:\n    paths: [src/**]\n    paths-ignore: [docs/**]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "paths")
	assert.Contains(t, errs[0].Message, "paths-ignore")
}

func TestRule_ScheduleNotArray(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  schedule: not-an-array\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "schedule")
	assert.Contains(t, errs[0].Message, "must be a sequence")
}

func TestRule_ScheduleMissingCron(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  schedule:\n    - interval: daily\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "schedule")
	assert.Contains(t, errs[0].Message, "cron")
}

func TestRule_WorkflowDispatchUnknownKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  workflow_dispatch:\n    unknown: value\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "workflow_dispatch")
	assert.Contains(t, errs[0].Message, "unknown key")
}

func TestRule_WorkflowDispatchInputUnknownKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  workflow_dispatch:\n    inputs:\n      myinput:\n        description: test\n        unknown_prop: value\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "workflow_dispatch")
	assert.Contains(t, errs[0].Message, "myinput")
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "unknown_prop")
}

func TestRule_ScheduleEntryNotMapping(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  schedule:\n    - \"0 0 * * *\"\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "schedule")
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestRule_OnSequenceNonStringItem(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on:\n  - push\n  - 123\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "on")
	assert.Contains(t, errs[0].Message, "string")
}

func TestRule_ValidOnEvents(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"push string", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"push sequence", "on: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"push mapping", "on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"schedule", "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"workflow_dispatch", "on:\n  workflow_dispatch:\n    inputs:\n      name:\n        required: true\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"workflow_dispatch null", "on:\n  workflow_dispatch:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
		{"pull_request null", "on:\n  push:\n    branches: [main]\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
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
