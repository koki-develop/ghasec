package invalidaction_test

import (
	"testing"

	invalidaction "github.com/koki-develop/ghasec/rules/invalid-action"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_RunsNotMapping(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns: not-a-mapping\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "runs")
	assert.Contains(t, errs[0].Message, "must be a mapping")
}

func TestRule_RunsMissingUsing(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "using")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_RunsUsingNotString(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: true\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "using")
	assert.Contains(t, errs[0].Message, "must be a string")
	assert.Contains(t, errs[0].Message, "Bool")
}

func TestRule_RunsUnknownUsing(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: python3\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "using")
	assert.Contains(t, errs[0].Message, "unknown")
	assert.Contains(t, errs[0].Message, "python3")
}

func TestRule_JSRunsMissingMain(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: node20\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "main")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_JSRunsUnknownKey(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: node20\n  main: index.js\n  foo: bar\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_CompositeRunsMissingSteps(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "steps")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_CompositeRunsStepsNotSequence(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps: not-a-sequence\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "steps")
	assert.Contains(t, errs[0].Message, "must be a sequence")
}

func TestRule_CompositeRunsValid(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n")
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_DockerRunsMissingImage(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: docker\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "image")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_DockerRunsUnknownKey(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: docker\n  image: Dockerfile\n  foo: bar\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_JSRunsValidAllKeys(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: node20\n  main: index.js\n  pre: setup.js\n  pre-if: always()\n  post: cleanup.js\n  post-if: always()\n")
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_DockerRunsValidAllKeys(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nruns:\n  using: docker\n  image: Dockerfile\n  env:\n    FOO: bar\n  entrypoint: /entrypoint.sh\n  pre-entrypoint: /pre.sh\n  pre-if: always()\n  post-entrypoint: /post.sh\n  post-if: always()\n  args:\n    - hello\n")
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func newRule() *invalidaction.Rule {
	return &invalidaction.Rule{}
}
