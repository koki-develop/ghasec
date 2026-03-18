package parser_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/koki-develop/ghasec/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Run("parses valid YAML", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "valid.yml")
		require.NoError(t, os.WriteFile(path, []byte("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"), 0o644))

		f, err := parser.Parse(path)
		require.NoError(t, err)
		assert.NotNil(t, f)
		assert.NotEmpty(t, f.Docs)
	})

	t.Run("returns error for invalid YAML", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "invalid.yml")
		require.NoError(t, os.WriteFile(path, []byte("key: [unclosed\n"), 0o644))

		_, err := parser.Parse(path)
		assert.Error(t, err)
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		_, err := parser.Parse("/nonexistent/file.yml")
		assert.Error(t, err)
	})
}
