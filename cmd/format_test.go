package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormat_IsValid(t *testing.T) {
	tests := []struct {
		format Format
		valid  bool
	}{
		{FormatDefault, true},
		{FormatGitHubActions, true},
		{FormatMarkdown, true},
		{FormatSARIF, true},
		{Format("unknown"), false},
		{Format(""), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.format.IsValid())
		})
	}
}

func TestFormat_Set(t *testing.T) {
	var f Format
	require.NoError(t, f.Set("sarif"))
	assert.Equal(t, FormatSARIF, f)

	require.NoError(t, f.Set("default"))
	assert.Equal(t, FormatDefault, f)

	err := f.Set("invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown format "invalid"`)
}

func TestFormat_String(t *testing.T) {
	assert.Equal(t, "default", FormatDefault.String())
	assert.Equal(t, "sarif", FormatSARIF.String())
}

func TestFormat_Type(t *testing.T) {
	assert.Equal(t, "string", FormatDefault.Type())
}
