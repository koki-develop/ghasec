package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/koki-develop/ghasec/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, tagName string) *github.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": tagName})
	}))
	t.Cleanup(srv.Close)
	return github.NewClient(github.WithBaseURL(srv.URL), github.WithToken(""))
}

func newTestClientError(t *testing.T) *github.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return github.NewClient(github.WithBaseURL(srv.URL), github.WithToken(""))
}

func TestCheckNewVersionAvailable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")
	client := newTestClient(t, "v0.6.0")

	res := check(context.Background(), client, "0.5.0", cPath)
	require.NotNil(t, res)
	assert.Equal(t, "0.5.0", res.CurrentVersion)
	assert.Equal(t, "0.6.0", res.NewVersion)
}

func TestCheckAlreadyLatest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")
	client := newTestClient(t, "v0.5.0")

	res := check(context.Background(), client, "0.5.0", cPath)
	assert.Nil(t, res)
}

func TestCheckUnparseableCurrentVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")
	client := newTestClient(t, "v0.6.0")

	res := check(context.Background(), client, "dev", cPath)
	require.NotNil(t, res)
	assert.Equal(t, "dev", res.CurrentVersion)
	assert.Equal(t, "0.6.0", res.NewVersion)
}

func TestCheckUnparseableLatestVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")
	client := newTestClient(t, "invalid")

	res := check(context.Background(), client, "0.5.0", cPath)
	assert.Nil(t, res)
}

func TestCheckUsesCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")

	// Pre-populate cache
	c := &cache{
		LatestVersion: "0.7.0",
		CheckedAt:     time.Now().UTC(),
	}
	require.NoError(t, writeCache(cPath, c))

	// Server returns different version — should not be called
	client := newTestClient(t, "v0.8.0")
	res := check(context.Background(), client, "0.5.0", cPath)
	require.NotNil(t, res)
	assert.Equal(t, "0.7.0", res.NewVersion) // from cache, not API
}

func TestCheckSuppressesNotification(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")

	c := &cache{
		LatestVersion:   "0.6.0",
		CheckedAt:       time.Now().UTC(),
		NotifiedAt:      time.Now().UTC(),
		NotifiedVersion: "0.6.0",
	}
	require.NoError(t, writeCache(cPath, c))

	client := newTestClient(t, "v0.6.0")
	res := check(context.Background(), client, "0.5.0", cPath)
	assert.Nil(t, res) // suppressed
}

func TestCheckAPIError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")
	client := newTestClientError(t)

	res := check(context.Background(), client, "0.5.0", cPath)
	assert.Nil(t, res) // errors are silently ignored
}

func TestCheckEmptyCachePath(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, "v0.6.0")
	res := check(context.Background(), client, "0.5.0", "")
	assert.Nil(t, res)
}

func TestMarkNotifiedEmptyPath(t *testing.T) {
	t.Parallel()
	markNotified("0.6.0", "") // should not panic or write to CWD
}

func TestMarkNotified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cPath := filepath.Join(dir, "update.json")

	c := &cache{
		LatestVersion: "0.6.0",
		CheckedAt:     time.Now().UTC(),
	}
	require.NoError(t, writeCache(cPath, c))

	markNotified("0.6.0", cPath)

	got, err := readCache(cPath)
	require.NoError(t, err)
	assert.Equal(t, "0.6.0", got.NotifiedVersion)
	assert.WithinDuration(t, time.Now().UTC(), got.NotifiedAt, 5*time.Second)
}
