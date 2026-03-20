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
	t.Run("finds workflows and actions", func(t *testing.T) {
		dir := t.TempDir()
		workflowDir := filepath.Join(dir, ".github", "workflows")
		require.NoError(t, os.MkdirAll(workflowDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte("on: push"), 0o644))

		actionDir := filepath.Join(dir, "my-action")
		require.NoError(t, os.MkdirAll(actionDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte("name: test"), 0o644))

		res, err := discover.Discover(dir)
		require.NoError(t, err)
		require.Len(t, res.Workflows, 1)
		assert.Equal(t, "ci.yml", filepath.Base(res.Workflows[0]))
		require.Len(t, res.Actions, 1)
		assert.Equal(t, "action.yml", filepath.Base(res.Actions[0]))
	})

	t.Run("finds action.yaml variant", func(t *testing.T) {
		dir := t.TempDir()
		actionDir := filepath.Join(dir, "my-action")
		require.NoError(t, os.MkdirAll(actionDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yaml"), []byte("name: test"), 0o644))

		res, err := discover.Discover(dir)
		require.NoError(t, err)
		assert.Empty(t, res.Workflows)
		require.Len(t, res.Actions, 1)
		assert.Equal(t, "action.yaml", filepath.Base(res.Actions[0]))
	})

	t.Run("finds actions in subdirectories", func(t *testing.T) {
		dir := t.TempDir()
		nested := filepath.Join(dir, "actions", "setup", "node")
		require.NoError(t, os.MkdirAll(nested, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(nested, "action.yml"), []byte("name: test"), 0o644))

		res, err := discover.Discover(dir)
		require.NoError(t, err)
		require.Len(t, res.Actions, 1)
		assert.Contains(t, res.Actions[0], filepath.Join("actions", "setup", "node"))
	})

	t.Run("excludes .git and node_modules", func(t *testing.T) {
		dir := t.TempDir()
		for _, excluded := range []string{".git", "node_modules"} {
			excDir := filepath.Join(dir, excluded)
			require.NoError(t, os.MkdirAll(excDir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(excDir, "action.yml"), []byte("name: test"), 0o644))
		}

		res, err := discover.Discover(dir)
		require.NoError(t, err)
		assert.Empty(t, res.Actions)
	})

	t.Run(".github/workflows/action.yml goes to workflows only", func(t *testing.T) {
		dir := t.TempDir()
		workflowDir := filepath.Join(dir, ".github", "workflows")
		require.NoError(t, os.MkdirAll(workflowDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(workflowDir, "action.yml"), []byte("on: push"), 0o644))

		res, err := discover.Discover(dir)
		require.NoError(t, err)
		require.Len(t, res.Workflows, 1)
		assert.Equal(t, "action.yml", filepath.Base(res.Workflows[0]))
		assert.Empty(t, res.Actions)
	})

	t.Run("returns empty result when nothing found", func(t *testing.T) {
		dir := t.TempDir()
		res, err := discover.Discover(dir)
		require.NoError(t, err)
		assert.Empty(t, res.Workflows)
		assert.Empty(t, res.Actions)
	})
}
