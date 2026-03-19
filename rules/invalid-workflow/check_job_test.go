package invalidworkflow_test

import (
	"testing"

	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_UnknownJobKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    unknown: value\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "unknown")
}

func TestRule_UnknownReusableJobKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n    unknown: value\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "unknown")
}

func TestRule_StrategyMissingMatrix(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    strategy:\n      fail-fast: false\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "strategy")
	assert.Contains(t, errs[0].Message, "matrix")
}

func TestRule_JobConcurrencyMissingGroup(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    concurrency:\n      cancel-in-progress: true\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "concurrency")
	assert.Contains(t, errs[0].Message, "group")
}

func TestRule_JobInvalidDefaults(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    defaults: notamap\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "defaults")
	assert.Contains(t, errs[0].Message, "must be a mapping")
}

func TestRule_ValidJobKeysNormalJob(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, `on: push
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    permissions:
      contents: read
    needs: [setup]
    if: success()
    environment: production
    concurrency:
      group: build
      cancel-in-progress: true
    outputs:
      result: steps.build.outputs.result
    env:
      FOO: bar
    defaults:
      run:
        shell: bash
    timeout-minutes: 30
    strategy:
      matrix:
        os: [ubuntu-latest]
    continue-on-error: false
    container: node:18
    services:
      redis:
        image: redis
    steps:
      - run: echo hi
  setup:
    runs-on: ubuntu-latest
    steps:
      - run: echo setup
`)
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_RunsOnExpression(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_RunsOnMappingUnknownKey(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on:\n      foo: bar\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_RunsOnMappingValidKeys(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on:\n      group: my-group\n      labels: [self-hosted, linux]\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_RunsOnSequenceInvalidElement(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: [self-hosted, 123]\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs-on")
	assert.Contains(t, errs[0].Message, "sequence elements must be strings")
}

func TestRule_RunsOnSequenceWithExpression(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: [self-hosted, \"${{ matrix.label }}\"]\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_StrategyNotMapping(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    strategy: invalid\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "strategy")
	assert.Contains(t, errs[0].Message, "mapping")
}

func TestRule_StrategyExpression(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    strategy: ${{ fromJSON(needs.matrix.outputs.matrix) }}\n    steps:\n      - run: echo hi\n")
	errs := r.Check(m)
	assert.Empty(t, errs)
}

func TestRule_ValidJobKeysReusableJob(t *testing.T) {
	r := &invalidworkflow.Rule{}
	m := parseMapping(t, `on: push
jobs:
  call:
    name: Call workflow
    uses: org/repo/.github/workflows/ci.yml@main
    permissions:
      contents: read
    needs: [setup]
    if: success()
    with:
      param: value
    secrets:
      token: secret
    concurrency:
      group: call
    outputs:
      result: steps.call.outputs.result
    strategy:
      matrix:
        os: [ubuntu-latest]
  setup:
    runs-on: ubuntu-latest
    steps:
      - run: echo setup
`)
	errs := r.Check(m)
	assert.Empty(t, errs)
}
