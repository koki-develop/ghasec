package invalidaction_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_OutputsNotMapping(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\noutputs: not-a-mapping\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "outputs")
	assert.Contains(t, errs[0].Message, "must be a mapping")
}

func TestRule_OutputJSUnknownKeyValue(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\noutputs:\n  result:\n    description: the result\n    value: something\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "output")
	assert.Contains(t, errs[0].Message, "result")
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "value")
}

func TestRule_OutputCompositeMissingValue(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\noutputs:\n  result:\n    description: the result\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "value")
	assert.Contains(t, errs[0].Message, "is required")
}

func TestRule_OutputCompositeValid(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\noutputs:\n  result:\n    description: the result\n    value: ${{ steps.step1.outputs.result }}\nruns:\n  using: composite\n  steps:\n    - id: step1\n      run: echo hi\n      shell: bash\n")
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_OutputNonMappingEntry(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\noutputs:\n  result: not-a-mapping\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must be a mapping")
}
