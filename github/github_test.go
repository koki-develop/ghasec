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
	assert.True(t, c.RateLimitHit(), "rate limit flag should be set for 403 with rate limit message")
}

func TestRateLimitDetection_429(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "rate limit exceeded"})
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.True(t, c.RateLimitHit())
}

func TestRateLimitDetection_403WithRemainingZero(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Ratelimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "forbidden"})
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.True(t, c.RateLimitHit())
}

func TestRateLimitDetection_403WithSecondaryRateLimitMessage(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "You have exceeded a secondary rate limit."})
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.True(t, c.RateLimitHit())
}

func TestRateLimitDetection_403WithoutRateLimit(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Resource not accessible by integration"})
	})

	_, err := c.ResolveTagSHA(context.Background(), "actions", "checkout", "v4")
	require.Error(t, err)
	assert.False(t, c.RateLimitHit(), "non-rate-limit 403 should not set the flag")
}

func TestRateLimitDetection_VerifyCommit_TagsEndpoint(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "rate limit exceeded"})
	})

	_, err := c.VerifyCommit(context.Background(), "actions", "checkout", "aaaa")
	require.Error(t, err)
	assert.True(t, c.RateLimitHit(), "rate limit flag should be set via doGetPaginated path")
}

func TestRateLimitDetection_VerifyCommit_CompareEndpoint(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		default:
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "rate limit exceeded"})
		}
	})

	_, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.Error(t, err)
	assert.True(t, c.RateLimitHit(), "rate limit flag should be set via compareCommit path")
}

func TestHasToken(t *testing.T) {
	withToken := NewClient(WithBaseURL("http://localhost"), WithToken("ghp_test"))
	assert.True(t, withToken.HasToken())

	withoutToken := NewClient(WithBaseURL("http://localhost"), WithToken(""))
	assert.False(t, withoutToken.HasToken())
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
	assert.Contains(t, err.Error(), "failed to resolve tag")
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
	for range 10 {
		wg.Go(func() {
			got, err := c.ResolveTagSHA(ctx, "actions", "checkout", "v4")
			assert.NoError(t, err)
			assert.Equal(t, sha, got)
		})
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

// --- VerifyCommit tests ---

func repoTagsJSON(tags ...repoTag) []byte {
	b, _ := json.Marshal(tags)
	return b
}

func TestVerifyCommit_TagMatch(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON(repoTag{
				Name: "v4",
				Commit: struct {
					SHA string `json:"sha"`
				}{SHA: sha},
			}))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyCommit_BranchReachable_Behind(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		case "/repos/actions/checkout/compare/main..." + sha:
			_ = json.NewEncoder(w).Encode(compareResponse{Status: "behind"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyCommit_BranchReachable_Identical(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		case "/repos/actions/checkout/compare/main..." + sha:
			_ = json.NewEncoder(w).Encode(compareResponse{Status: "identical"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyCommit_NotReachable(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		case "/repos/actions/checkout/compare/main..." + sha:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyCommit_TagListError(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
	})

	_, err := c.VerifyCommit(context.Background(), "actions", "checkout", "aaaa")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestVerifyCommit_BranchListError(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
		}
	})

	_, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestVerifyCommit_NonDefaultBranchReachable(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}, {Name: "releases/v2"}})
		case "/repos/actions/checkout/compare/main..." + sha:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		case "/repos/actions/checkout/compare/releases/v2..." + sha:
			_ = json.NewEncoder(w).Encode(compareResponse{Status: "behind"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyCommit_Cache(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	var callCount atomic.Int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON(repoTag{
				Name: "v4",
				Commit: struct {
					SHA string `json:"sha"`
				}{SHA: sha},
			}))
		}
	})

	ctx := context.Background()
	ok1, err := c.VerifyCommit(ctx, "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok1)

	ok2, err := c.VerifyCommit(ctx, "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok2)

	assert.Equal(t, int32(1), callCount.Load(), "second call should hit cache")
}

func TestVerifyCommit_PaginatedTags(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/repos/actions/checkout/tags" && r.URL.Query().Get("page") != "2":
			w.Header().Set("Link", `<`+r.URL.Path+`?page=2>; rel="next"`)
			_, _ = w.Write(repoTagsJSON(repoTag{
				Name: "v3",
				Commit: struct {
					SHA string `json:"sha"`
				}{SHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			}))
		case r.URL.Path == "/repos/actions/checkout/tags" && r.URL.Query().Get("page") == "2":
			_, _ = w.Write(repoTagsJSON(repoTag{
				Name: "v4",
				Commit: struct {
					SHA string `json:"sha"`
				}{SHA: sha},
			}))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyCommit_PaginatedTagsEarlyReturn(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	var page2Fetched atomic.Bool
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/repos/actions/checkout/tags" && r.URL.Query().Get("page") != "2":
			w.Header().Set("Link", `<`+r.URL.Path+`?page=2>; rel="next"`)
			_, _ = w.Write(repoTagsJSON(repoTag{
				Name: "v4",
				Commit: struct {
					SHA string `json:"sha"`
				}{SHA: sha},
			}))
		case r.URL.Path == "/repos/actions/checkout/tags" && r.URL.Query().Get("page") == "2":
			page2Fetched.Store(true)
			_, _ = w.Write(repoTagsJSON())
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, page2Fetched.Load(), "page 2 should not be fetched when match is on page 1")
}

func TestVerifyCommit_BranchCacheAcrossVerifications(t *testing.T) {
	sha1 := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	sha2 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var branchCallCount atomic.Int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			branchCallCount.Add(1)
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		default:
			_ = json.NewEncoder(w).Encode(compareResponse{Status: "behind"})
		}
	})

	ctx := context.Background()
	_, err := c.VerifyCommit(ctx, "actions", "checkout", sha1)
	require.NoError(t, err)

	_, err = c.VerifyCommit(ctx, "actions", "checkout", sha2)
	require.NoError(t, err)

	assert.Equal(t, int32(1), branchCallCount.Load(), "branch list should be cached across verifications for the same repo")
}

func TestVerifyCommit_CompareAPIError(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		case "/repos/actions/checkout/compare/main..." + sha:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
		}
	})

	_, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestVerifyCommit_ZeroBranches(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyCommit_CompareAheadIsNotReachable(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		case "/repos/actions/checkout/compare/main..." + sha:
			_ = json.NewEncoder(w).Encode(compareResponse{Status: "ahead"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyCommit_CompareDivergedIsNotReachable(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON())
		case "/repos/actions/checkout/branches":
			_ = json.NewEncoder(w).Encode([]branch{{Name: "main"}})
		case "/repos/actions/checkout/compare/main..." + sha:
			_ = json.NewEncoder(w).Encode(compareResponse{Status: "diverged"})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ok, err := c.VerifyCommit(context.Background(), "actions", "checkout", sha)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyCommit_PopulatesResolveTagSHACache(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	var resolveAPICalled atomic.Bool
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/actions/checkout/tags":
			_, _ = w.Write(repoTagsJSON(repoTag{
				Name: "v4",
				Commit: struct {
					SHA string `json:"sha"`
				}{SHA: sha},
			}))
		case "/repos/actions/checkout/git/ref/tags/v4":
			resolveAPICalled.Store(true)
			_, _ = w.Write(refJSON("commit", sha))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ctx := context.Background()

	// VerifyCommit scans tags and should populate the ResolveTagSHA cache.
	ok, err := c.VerifyCommit(ctx, "actions", "checkout", sha)
	require.NoError(t, err)
	assert.True(t, ok)

	// ResolveTagSHA should hit the cache without making any API call.
	got, err := c.ResolveTagSHA(ctx, "actions", "checkout", "v4")
	require.NoError(t, err)
	assert.Equal(t, sha, got)
	assert.False(t, resolveAPICalled.Load(), "ResolveTagSHA should use cache populated by VerifyCommit")
}

func TestCompareCommit_PerPageParam(t *testing.T) {
	sha := "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.Equal(t, "1", r.URL.Query().Get("per_page"), "compare API should use per_page=1")
		_ = json.NewEncoder(w).Encode(compareResponse{Status: "behind"})
	})

	status, err := c.compareCommit(context.Background(), "actions", "checkout", "main", sha)
	require.NoError(t, err)
	assert.Equal(t, "behind", status)
}

func TestLatestRelease(t *testing.T) {
	t.Parallel()
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/koki-develop/ghasec/releases/latest", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": "v0.6.0"})
	})

	tag, err := c.LatestRelease(context.Background(), "koki-develop", "ghasec")
	require.NoError(t, err)
	assert.Equal(t, "v0.6.0", tag)
}

func TestLatestReleaseNotFound(t *testing.T) {
	t.Parallel()
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	})

	_, err := c.LatestRelease(context.Background(), "koki-develop", "ghasec")
	require.Error(t, err)
}

func TestParseLinkNext(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		baseURL string
		want    string
	}{
		{"empty", "", "https://api.github.com", ""},
		{"no next", `<https://api.github.com/repos/a/b/tags?page=1>; rel="prev"`, "https://api.github.com", ""},
		{"has next", `<https://api.github.com/repos/a/b/tags?page=2>; rel="next"`, "https://api.github.com", "/repos/a/b/tags?page=2"},
		{"next is second", `<https://api.github.com/repos/a/b/tags?page=1>; rel="prev", <https://api.github.com/repos/a/b/tags?page=3>; rel="next"`, "https://api.github.com", "/repos/a/b/tags?page=3"},
		{"malformed no angle", `https://api.github.com/repos/a/b/tags?page=2; rel="next"`, "https://api.github.com", ""},
		{"strips base url", `</repos/a/b/tags?page=2>; rel="next"`, "", "/repos/a/b/tags?page=2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLinkNext(tt.header, tt.baseURL)
			assert.Equal(t, tt.want, got)
		})
	}
}
