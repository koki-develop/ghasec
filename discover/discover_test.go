package discover_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/koki-develop/ghasec/discover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	t.Run("finds yml and yaml files", func(t *testing.T) {
		dir := t.TempDir()
		workflowDir := filepath.Join(dir, ".github", "workflows")
		require.NoError(t, os.MkdirAll(workflowDir, 0o755))
		for _, name := range []string{"ci.yml", "deploy.yaml", "notes.txt"} {
			require.NoError(t, os.WriteFile(filepath.Join(workflowDir, name), []byte("on: push"), 0o644))
		}

		files, err := discover.Discover(dir)
		require.NoError(t, err)

		basenames := make([]string, len(files))
		for i, f := range files {
			basenames[i] = filepath.Base(f)
		}
		assert.ElementsMatch(t, []string{"ci.yml", "deploy.yaml"}, basenames)
	})

	t.Run("returns empty slice when directory does not exist", func(t *testing.T) {
		files, err := discover.Discover("/nonexistent")
		require.NoError(t, err)
		assert.Empty(t, files)
	})

	t.Run("returns empty slice when no workflow files", func(t *testing.T) {
		dir := t.TempDir()
		workflowDir := filepath.Join(dir, ".github", "workflows")
		require.NoError(t, os.MkdirAll(workflowDir, 0o755))

		files, err := discover.Discover(dir)
		require.NoError(t, err)
		assert.Empty(t, files)
	})
}
