package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(WithBaseURL(srv.URL), WithToken(""))
}

func refJSON(typ, sha string) []byte {
	ref := gitRef{Object: struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}{Type: typ, SHA: sha}}
	b, _ := json.Marshal(ref)
	return b
}

func TestResolveTagSHA_LightweightTag(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/actions/checkout/git/ref/tags/v4", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(refJSON("commit", sha))
	})

	got, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.NoError(t, err)
	assert.Equal(t, sha, got)
}

func TestResolveTagSHA_AnnotatedTag(t *testing.T) {
	tagObjectSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitSHA := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/v4":
			_, _ = w.Write(refJSON("tag", tagObjectSHA))
		case "/repos/actions/checkout/git/tags/" + tagObjectSHA:
			_, _ = w.Write(refJSON("commit", commitSHA))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	got, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.NoError(t, err)
	assert.Equal(t, commitSHA, got)
}

func TestResolveTagSHA_UnexpectedRefType(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(refJSON("blob", "aaaa"))
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unexpected ref object type "blob"`)
}

func TestResolveTagSHA_AnnotatedTagNotPointingToCommit(t *testing.T) {
	tagObjectSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/v4":
			_, _ = w.Write(refJSON("tag", tagObjectSHA))
		case "/repos/actions/checkout/git/tags/" + tagObjectSHA:
			_, _ = w.Write(refJSON("tree", "bbbb"))
		}
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `expected tag to point to commit, got "tree"`)
}

func TestResolveTagSHA_404(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v999")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
	assert.Contains(t, err.Error(), "Not Found")
}

func TestResolveTagSHA_403WithMessage(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "API rate limit exceeded"})
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 403")
	assert.Contains(t, err.Error(), "API rate limit exceeded")
}

func TestResolveTagSHA_NonJSONErrorBody(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 502")
}

func TestResolveTagSHA_InvalidJSON(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{invalid"))
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode")
}

func TestResolveTagSHA_Cache(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	var callCount atomic.Int32

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(refJSON("commit", sha))
	})

	ctx := context.Background()
	got1, err := c.ResolveTagSHA(ctx, "actions", "checkout", "v4")
	require.NoError(t, err)
	assert.Equal(t, sha, got1)

	got2, err := c.ResolveTagSHA(ctx, "actions", "checkout", "v4")
	require.NoError(t, err)
	assert.Equal(t, sha, got2)

	assert.Equal(t, int32(1), callCount.Load(), "second call should hit cache")
}

func TestResolveTagSHA_CacheError(t *testing.T) {
	var callCount atomic.Int32

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	})

	ctx := context.Background()
	_, err1 := c.ResolveTagSHA(ctx, "actions", "checkout", "v999")
	require.Error(t, err1)

	_, err2 := c.ResolveTagSHA(ctx, "actions", "checkout", "v999")
	require.Error(t, err2)

	assert.Equal(t, int32(1), callCount.Load(), "error should be cached too")
}

func TestResolveTagSHA_CacheSeparateKeys(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/v4":
			_, _ = w.Write(refJSON("commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
		case "/repos/actions/setup-go/git/ref/tags/v5":
			_, _ = w.Write(refJSON("commit", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
		}
	})

	ctx := context.Background()
	got1, err := c.ResolveTagSHA(ctx, "actions", "checkout", "v4")
	require.NoError(t, err)
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", got1)

	got2, err := c.ResolveTagSHA(ctx, "actions", "setup-go", "v5")
	require.NoError(t, err)
	assert.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", got2)
}

func TestResolveTagSHA_Singleflight(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	var callCount atomic.Int32

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(refJSON("commit", sha))
	})

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.ResolveTagSHA(ctx, "actions", "checkout", "v4")
			assert.NoError(t, err)
			assert.Equal(t, sha, got)
		}()
	}
	wg.Wait()

	assert.LessOrEqual(t, callCount.Load(), int32(2), "singleflight should deduplicate concurrent calls")
}

func TestResolveTagSHA_AuthorizationHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(refJSON("commit", "aaaa"))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(WithBaseURL(srv.URL), WithToken("test-token"))
	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.NoError(t, err)
}

func TestResolveTagSHA_NoAuthorizationHeaderWhenNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(refJSON("commit", "aaaa"))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(WithBaseURL(srv.URL), WithToken(""))
	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.NoError(t, err)
}

func TestResolveTagSHA_DereferenceTagError(t *testing.T) {
	tagObjectSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/v4":
			_, _ = w.Write(refJSON("tag", tagObjectSHA))
		case "/repos/actions/checkout/git/tags/" + tagObjectSHA:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
		}
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}
