package invalidaction_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_InputsNotMapping(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\ninputs: not-a-mapping\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "inputs")
	assert.Contains(t, errs[0].Message, "must be a mapping")
}

func TestRule_InputUnknownKey(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\ninputs:\n  token:\n    description: token\n    foo: bar\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "input")
	assert.Contains(t, errs[0].Message, "token")
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_InputValidKeys(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\ninputs:\n  token:\n    description: the token\n    required: true\n    default: abc\n    deprecationMessage: use something else\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_InputNonMappingEntry(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\ninputs:\n  token: not-a-mapping\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "must be a mapping")
}
