package invalidaction_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_BrandingNotMapping(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nbranding: not-a-mapping\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "branding")
	assert.Contains(t, errs[0].Message, "must be a mapping")
}

func TestRule_BrandingUnknownKey(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nbranding:\n  icon: check\n  color: green\n  foo: bar\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unknown key")
	assert.Contains(t, errs[0].Message, "foo")
}

func TestRule_BrandingInvalidColor(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nbranding:\n  icon: check\n  color: pink\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "color")
	assert.Contains(t, errs[0].Message, "unknown")
	assert.Contains(t, errs[0].Message, "pink")
}

func TestRule_BrandingInvalidIcon(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nbranding:\n  icon: foobar\n  color: green\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "icon")
	assert.Contains(t, errs[0].Message, "unknown")
	assert.Contains(t, errs[0].Message, "foobar")
}

func TestRule_BrandingNonStringColor(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nbranding:\n  icon: check\n  color: 123\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "color")
	assert.Contains(t, errs[0].Message, "must be a string")
}

func TestRule_BrandingNonStringIcon(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nbranding:\n  icon: 123\n  color: green\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "icon")
	assert.Contains(t, errs[0].Message, "must be a string")
}

func TestRule_BrandingValid(t *testing.T) {
	r := newRule()
	m := parseMapping(t, "name: test\ndescription: test\nbranding:\n  icon: check\n  color: green\nruns:\n  using: node20\n  main: index.js\n")
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}
