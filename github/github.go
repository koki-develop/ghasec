package github

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

const defaultBaseURL = "https://api.github.com"

type Client struct {
	httpClient    *http.Client
	baseURL       string
	token         string
	rateLimitHit  atomic.Bool
	cache         sync.Map // key: "owner/repo@tag", value: cacheEntry
	flight        singleflight.Group
	verifyCache   sync.Map // key: "verify:owner/repo@sha", value: verifyCacheEntry
	verifyFlight  singleflight.Group
	branchCache   sync.Map // key: "owner/repo", value: branchCacheEntry
	branchFlight  singleflight.Group
	archiveCache  sync.Map // key: "owner/repo", value: archiveCacheEntry
	archiveFlight singleflight.Group
}

type cacheEntry struct {
	sha string
	err error
}

type Option func(*Client)

func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = url }
}

func WithToken(token string) Option {
	return func(c *Client) { c.token = token }
}

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    defaultBaseURL,
		token:      cmp.Or(os.Getenv("GHASEC_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN")),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// gitRef is the common JSON structure shared across multiple git reference endpoints
// (git/ref/tags, git/tags).
type gitRef struct {
	Ref    string `json:"ref"`
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

type release struct {
	TagName string `json:"tag_name"`
}

type repoTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

type compareResponse struct {
	Status string `json:"status"`
}

type branch struct {
	Name string `json:"name"`
}

type verifyCacheEntry struct {
	ok  bool
	err error
}

type branchCacheEntry struct {
	branches []branch
	err      error
}

type archiveCacheEntry struct {
	archived bool
	err      error
}

type repoResponse struct {
	Archived bool `json:"archived"`
}

// ResolveTagSHA resolves a git tag to its underlying commit SHA.
// For annotated tags, it dereferences the tag object to find the commit.
// Results are cached to avoid duplicate API calls for the same owner/repo@tag.
func (c *Client) ResolveTagSHA(ctx context.Context, owner, repo, tag string) (string, error) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, tag)
	if v, ok := c.cache.Load(key); ok {
		entry := v.(cacheEntry)
		return entry.sha, entry.err
	}

	v, err, _ := c.flight.Do(key, func() (any, error) {
		sha, err := c.resolveTagSHA(ctx, owner, repo, tag)
		c.cache.Store(key, cacheEntry{sha: sha, err: err})
		return sha, err
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (c *Client) resolveTagSHA(ctx context.Context, owner, repo, tag string) (string, error) {
	ref, err := c.getRef(ctx, owner, repo, tag)
	if err != nil {
		return "", err
	}

	switch ref.Object.Type {
	case "commit":
		return ref.Object.SHA, nil
	case "tag":
		return c.dereferenceTag(ctx, owner, repo, ref.Object.SHA)
	default:
		return "", fmt.Errorf("unexpected ref object type %q", ref.Object.Type)
	}
}

// doGet performs a GET request to the given path, decodes the JSON response
// into result, and returns an error with errContext on non-200 status or decode failure.
func (c *Client) doGet(ctx context.Context, path string, result any, errContext string) error {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.apiError(resp, errContext)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("%s: %w", errContext, err)
	}
	return nil
}

func (c *Client) getRef(ctx context.Context, owner, repo, tag string) (*gitRef, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/ref/tags/%s", owner, repo, tag)
	var ref gitRef
	if err := c.doGet(ctx, path, &ref, fmt.Sprintf("failed to resolve tag %q on %s/%s", tag, owner, repo)); err != nil {
		return nil, err
	}
	return &ref, nil
}

func (c *Client) dereferenceTag(ctx context.Context, owner, repo, tagSHA string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/tags/%s", owner, repo, tagSHA)
	var ref gitRef
	if err := c.doGet(ctx, path, &ref, fmt.Sprintf("failed to dereference tag object %q on %s/%s", tagSHA, owner, repo)); err != nil {
		return "", err
	}

	if ref.Object.Type != "commit" {
		return "", fmt.Errorf("expected tag to point to commit, got %q", ref.Object.Type)
	}
	return ref.Object.SHA, nil
}

// LatestRelease fetches the latest release tag name for the given repository.
func (c *Client) LatestRelease(ctx context.Context, owner, repo string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/releases/latest", owner, repo)
	var rel release
	if err := c.doGet(ctx, path, &rel, fmt.Sprintf("failed to fetch latest release for %s/%s", owner, repo)); err != nil {
		return "", err
	}
	return rel.TagName, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// apiError builds an error from a non-200 GitHub API response,
// including the error message from the response body when available.
// It also detects rate limit errors (HTTP 429, or HTTP 403 with
// X-Ratelimit-Remaining: 0 or a "rate limit" message) and sets
// the rateLimitHit flag.
func (c *Client) apiError(resp *http.Response, errContext string) error {
	var body struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)

	if c.isRateLimited(resp, body.Message) {
		c.rateLimitHit.Store(true)
	}

	if body.Message != "" {
		return fmt.Errorf("%s: HTTP %d: %s", errContext, resp.StatusCode, body.Message)
	}
	return fmt.Errorf("%s: HTTP %d", errContext, resp.StatusCode)
}

func (c *Client) isRateLimited(resp *http.Response, message string) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode == http.StatusForbidden {
		if resp.Header.Get("X-Ratelimit-Remaining") == "0" {
			return true
		}
		if strings.Contains(strings.ToLower(message), "rate limit") {
			return true
		}
	}
	return false
}

// RateLimitHit reports whether any API call encountered a rate limit error.
func (c *Client) RateLimitHit() bool {
	return c.rateLimitHit.Load()
}

// HasToken reports whether the client was configured with a GitHub token.
func (c *Client) HasToken() bool {
	return c.token != ""
}

// IsArchived checks whether a repository is archived. Results are cached.
func (c *Client) IsArchived(ctx context.Context, owner, repo string) (bool, error) {
	key := fmt.Sprintf("%s/%s", owner, repo)
	if v, ok := c.archiveCache.Load(key); ok {
		entry := v.(archiveCacheEntry)
		return entry.archived, entry.err
	}

	v, err, _ := c.archiveFlight.Do(key, func() (any, error) {
		archived, err := c.isArchived(ctx, owner, repo)
		c.archiveCache.Store(key, archiveCacheEntry{archived: archived, err: err})
		return archived, err
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (c *Client) isArchived(ctx context.Context, owner, repo string) (bool, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	var r repoResponse
	if err := c.doGet(ctx, path, &r, fmt.Sprintf("failed to fetch repository metadata for %s/%s", owner, repo)); err != nil {
		return false, err
	}
	return r.Archived, nil
}

// VerifyCommit checks whether a commit SHA is reachable from any branch or tag
// in the given repository. Results are cached.
func (c *Client) VerifyCommit(ctx context.Context, owner, repo, sha string) (bool, error) {
	key := fmt.Sprintf("verify:%s/%s@%s", owner, repo, sha)
	if v, ok := c.verifyCache.Load(key); ok {
		entry := v.(verifyCacheEntry)
		return entry.ok, entry.err
	}

	v, err, _ := c.verifyFlight.Do(key, func() (any, error) {
		ok, err := c.verifyCommit(ctx, owner, repo, sha)
		c.verifyCache.Store(key, verifyCacheEntry{ok: ok, err: err})
		return ok, err
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (c *Client) verifyCommit(ctx context.Context, owner, repo, sha string) (bool, error) {
	// Phase 1: Check tags page by page (early return on match)
	found, err := c.checkTagsPaginated(ctx, owner, repo, sha)
	if err != nil {
		return false, err
	}
	if found {
		return true, nil
	}

	// Phase 2: Check branches with bounded concurrency
	branches, err := c.cachedListBranches(ctx, owner, repo)
	if err != nil {
		return false, err
	}

	const concurrency = 5
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		reachable bool
		err       error
	}
	results := make(chan result, len(branches))
	sem := make(chan struct{}, concurrency)

	for _, br := range branches {
		sem <- struct{}{}
		go func(branchName string) {
			defer func() { <-sem }()
			status, err := c.compareCommit(ctx, owner, repo, branchName, sha)
			if err != nil {
				results <- result{err: err}
				return
			}
			reachable := status == "behind" || status == "identical"
			if reachable {
				cancel()
			}
			results <- result{reachable: reachable}
		}(br.Name)
	}

	var firstErr error
	for range len(branches) {
		r := <-results
		if r.err != nil && firstErr == nil && !errors.Is(r.err, context.Canceled) {
			firstErr = r.err
		}
		if r.reachable {
			return true, nil
		}
	}
	if firstErr != nil {
		return false, firstErr
	}
	return false, nil
}

func (c *Client) checkTagsPaginated(ctx context.Context, owner, repo, sha string) (bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/tags", owner, repo)
	for path != "" {
		var page []repoTag
		nextPath, err := c.doGetPaginated(ctx, path, &page,
			fmt.Sprintf("failed to list tags on %s/%s", owner, repo))
		if err != nil {
			return false, err
		}
		for _, tag := range page {
			// Populate ResolveTagSHA cache as a side effect.
			c.cacheTagResolution(owner, repo, tag.Name, tag.Commit.SHA)
			if tag.Commit.SHA == sha {
				return true, nil
			}
		}
		path = nextPath
	}
	return false, nil
}

func (c *Client) cacheTagResolution(owner, repo, tag, commitSHA string) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, tag)
	c.cache.LoadOrStore(key, cacheEntry{sha: commitSHA})
}

func (c *Client) cachedListBranches(ctx context.Context, owner, repo string) ([]branch, error) {
	key := fmt.Sprintf("%s/%s", owner, repo)
	if v, ok := c.branchCache.Load(key); ok {
		entry := v.(branchCacheEntry)
		return entry.branches, entry.err
	}

	v, err, _ := c.branchFlight.Do(key, func() (any, error) {
		branches, err := c.listBranches(ctx, owner, repo)
		c.branchCache.Store(key, branchCacheEntry{branches: branches, err: err})
		return branches, err
	})
	if err != nil {
		return nil, err
	}
	return v.([]branch), nil
}

func (c *Client) listBranches(ctx context.Context, owner, repo string) ([]branch, error) {
	var all []branch
	path := fmt.Sprintf("/repos/%s/%s/branches", owner, repo)
	for path != "" {
		var page []branch
		nextPath, err := c.doGetPaginated(ctx, path, &page,
			fmt.Sprintf("failed to list branches on %s/%s", owner, repo))
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		path = nextPath
	}
	return all, nil
}

func (c *Client) compareCommit(ctx context.Context, owner, repo, base, sha string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/compare/%s...%s?per_page=1", owner, repo, base, sha)
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	// 404 means the commits share no common history (not reachable from this branch).
	// This is also returned if the repo was deleted between listBranches and this call,
	// but that race is unavoidable with the compare API.
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", c.apiError(resp, fmt.Sprintf("failed to compare %s...%s on %s/%s", base, sha, owner, repo))
	}

	var cr compareResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", fmt.Errorf("failed to compare %s...%s on %s/%s: %w", base, sha, owner, repo, err)
	}
	return cr.Status, nil
}

func (c *Client) doGetPaginated(ctx context.Context, path string, result any, errContext string) (string, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", c.apiError(resp, errContext)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return "", fmt.Errorf("%s: %w", errContext, err)
	}

	return parseLinkNext(resp.Header.Get("Link"), c.baseURL), nil
}

func parseLinkNext(header, baseURL string) string {
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end < 0 || end <= start {
			continue
		}
		link := part[start+1 : end]
		return strings.TrimPrefix(link, baseURL)
	}
	return ""
}
