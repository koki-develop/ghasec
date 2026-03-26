package update

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheReadWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "update.json")

	c := &cache{
		LatestVersion:   "0.6.0",
		CheckedAt:       time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC),
		NotifiedAt:      time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC),
		NotifiedVersion: "0.6.0",
	}
	err := writeCache(path, c)
	require.NoError(t, err)

	got, err := readCache(path)
	require.NoError(t, err)
	assert.Equal(t, c.LatestVersion, got.LatestVersion)
	assert.True(t, c.CheckedAt.Equal(got.CheckedAt))
	assert.True(t, c.NotifiedAt.Equal(got.NotifiedAt))
	assert.Equal(t, c.NotifiedVersion, got.NotifiedVersion)
}

func TestCacheReadNonexistent(t *testing.T) {
	t.Parallel()
	got, err := readCache("/nonexistent/path/update.json")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestCacheWriteCreatesDir(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	path := filepath.Join(dir, "update.json")

	c := &cache{LatestVersion: "1.0.0", CheckedAt: time.Now().UTC()}
	err := writeCache(path, c)
	require.NoError(t, err)

	_, err = os.Stat(path)
	assert.NoError(t, err)
}

func TestCacheCheckedFresh(t *testing.T) {
	t.Parallel()
	c := &cache{
		LatestVersion: "0.6.0",
		CheckedAt:     time.Now().UTC().Add(-1 * time.Hour),
	}
	assert.True(t, c.isCheckFresh())

	c.CheckedAt = time.Now().UTC().Add(-25 * time.Hour)
	assert.False(t, c.isCheckFresh())
}

func TestCacheNotifiedFresh(t *testing.T) {
	t.Parallel()
	c := &cache{
		NotifiedAt:      time.Now().UTC().Add(-1 * time.Hour),
		NotifiedVersion: "0.6.0",
	}
	assert.True(t, c.isNotifyFresh("0.6.0"))
	assert.False(t, c.isNotifyFresh("0.7.0"))

	c.NotifiedAt = time.Now().UTC().Add(-25 * time.Hour)
	assert.False(t, c.isNotifyFresh("0.6.0"))
}
