package github

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"golang.org/x/sync/singleflight"
)

const defaultBaseURL = "https://api.github.com"

// Client is a GitHub REST API client.
//
// Every error returned by a Client method describes the request that failed:
// what was requested and from which repository, followed by the cause (an
// HTTP status, a transport error, or a decoding error). The online rules show
// these errors to the user as they are, without adding context of their own.
type Client struct {
	httpClient       *http.Client
	baseURL          string
	token            string
	rateLimitHit     atomic.Bool
	cache            sync.Map // key: "owner/repo@tag", value: cacheEntry
	flight           singleflight.Group
	verifyCache      sync.Map // key: "verify:owner/repo@sha", value: verifyCacheEntry
	verifyFlight     singleflight.Group
	branchCache      sync.Map // key: "owner/repo", value: branchCacheEntry
	branchFlight     singleflight.Group
	branchRefCache   sync.Map // key: "owner/repo@branch", value: branchRefCacheEntry
	branchRefFlight  singleflight.Group
	onBranchCache    sync.Map // key: "owner/repo@branch...sha", value: onBranchCacheEntry
	onBranchFlight   singleflight.Group
	repoCache        sync.Map // key: "owner/repo", value: repoCacheEntry
	repoFlight       singleflight.Group
	actionFileCache  sync.Map // key: actionKey(owner, repo, subPath, ref), value: actionFileCacheEntry
	actionFileFlight singleflight.Group
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

type branchRefCacheEntry struct {
	exists bool
	err    error
}

type onBranchCacheEntry struct {
	onBranch bool
	err      error
}

type repoCacheEntry struct {
	repo *repoResponse
	err  error
}

type repoResponse struct {
	Archived bool `json:"archived"`
}

type contentResponse struct {
	Content string `json:"content"`
}

type actionFileCacheEntry struct {
	file *ast.File
	err  error
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
		sha, err := c.dereferenceTag(ctx, owner, repo, tag, ref.Object.SHA)
		var ae *APIError
		if errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound {
			// The tag ref exists, so a missing tag object is a resolution
			// failure, not a missing tag. Do not wrap err, so that callers
			// checking IsNotFound do not mistake it for a missing tag.
			return "", fmt.Errorf("tag %q on %s/%s points to a missing tag object %q: %s", tag, owner, repo, ref.Object.SHA, ae.status)
		}
		return sha, err
	default:
		return "", fmt.Errorf("tag %q on %s/%s points to a %s object, not a commit or tag object", tag, owner, repo, ref.Object.Type)
	}
}

// doGet performs a GET request to the given path, decodes the JSON response
// into result, and returns an error with errContext on non-200 status or decode failure.
func (c *Client) doGet(ctx context.Context, path string, result any, errContext string) error {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return requestError(errContext, err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return requestError(errContext, err)
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

// requestError wraps an error that ended a request before any response
// arrived. The *url.Error returned by net/http repeats the request method and
// URL, which errContext already describes, so only its cause is kept. The
// cause stays wrapped, so errors.Is still matches context.Canceled.
func requestError(errContext string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("%s: %w", errContext, err)
}

// repoPath returns the API path of a repository, "/repos/{owner}/{repo}",
// followed by the given already-escaped suffix. owner and repo come from
// workflow files, so they are escaped like every other user-supplied value
// in a request URL.
func repoPath(owner, repo, suffix string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + suffix
}

// escapeSegments escapes each slash-separated segment of s for use in a URL
// path and keeps the slashes. Git ref names ("release/v1") and file paths are
// sent to the GitHub API with their slashes as path separators, but any other
// reserved character (such as "#", "%" or "+") must not change the request.
func escapeSegments(s string) string {
	segments := strings.Split(s, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return strings.Join(segments, "/")
}

func (c *Client) getRef(ctx context.Context, owner, repo, tag string) (*gitRef, error) {
	path := repoPath(owner, repo, "/git/ref/tags/"+escapeSegments(tag))
	var ref gitRef
	if err := c.doGet(ctx, path, &ref, fmt.Sprintf("failed to resolve tag %q on %s/%s", tag, owner, repo)); err != nil {
		return nil, err
	}
	return &ref, nil
}

func (c *Client) dereferenceTag(ctx context.Context, owner, repo, tag, tagSHA string) (string, error) {
	path := repoPath(owner, repo, "/git/tags/"+url.PathEscape(tagSHA))
	var ref gitRef
	if err := c.doGet(ctx, path, &ref, fmt.Sprintf("failed to dereference tag object %q on %s/%s", tagSHA, owner, repo)); err != nil {
		return "", err
	}

	if ref.Object.Type != "commit" {
		return "", fmt.Errorf("tag %q on %s/%s points to a tag object that points to a %s object, not a commit", tag, owner, repo, ref.Object.Type)
	}
	return ref.Object.SHA, nil
}

// BranchExists reports whether a branch with the given name exists in the
// repository. A missing branch (HTTP 404) is reported as (false, nil); other
// API failures are returned as errors. Results are cached.
func (c *Client) BranchExists(ctx context.Context, owner, repo, branch string) (bool, error) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, branch)
	if v, ok := c.branchRefCache.Load(key); ok {
		entry := v.(branchRefCacheEntry)
		return entry.exists, entry.err
	}

	v, err, _ := c.branchRefFlight.Do(key, func() (any, error) {
		exists, err := c.branchExists(ctx, owner, repo, branch)
		c.branchRefCache.Store(key, branchRefCacheEntry{exists: exists, err: err})
		return exists, err
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (c *Client) branchExists(ctx context.Context, owner, repo, branch string) (bool, error) {
	path := repoPath(owner, repo, "/git/ref/heads/"+escapeSegments(branch))
	var ref gitRef
	err := c.doGet(ctx, path, &ref, fmt.Sprintf("failed to resolve branch %q on %s/%s", branch, owner, repo))
	if err == nil {
		return true, nil
	}
	if IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// BranchContainsCommit reports whether the commit sha is the head of the
// branch or one of its ancestors. The caller must already know that the
// branch exists: the compare API answers HTTP 404 both for a missing branch
// and for a commit that shares no history with it, and both are reported as
// (false, nil). Results are cached.
func (c *Client) BranchContainsCommit(ctx context.Context, owner, repo, branch, sha string) (bool, error) {
	key := fmt.Sprintf("%s/%s@%s...%s", owner, repo, branch, sha)
	if v, ok := c.onBranchCache.Load(key); ok {
		entry := v.(onBranchCacheEntry)
		return entry.onBranch, entry.err
	}

	v, err, _ := c.onBranchFlight.Do(key, func() (any, error) {
		status, err := c.compareCommit(ctx, owner, repo, branch, sha)
		onBranch := err == nil && isReachableStatus(status)
		c.onBranchCache.Store(key, onBranchCacheEntry{onBranch: onBranch, err: err})
		return onBranch, err
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

// isReachableStatus reports whether a compare status for base...head means
// that head is base itself or one of its ancestors.
func isReachableStatus(status string) bool {
	return status == "behind" || status == "identical"
}

// LatestRelease fetches the latest release tag name for the given repository.
func (c *Client) LatestRelease(ctx context.Context, owner, repo string) (string, error) {
	path := repoPath(owner, repo, "/releases/latest")
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

// APIError represents an error from a GitHub API response with the HTTP status code.
type APIError struct {
	StatusCode int
	// status is the response part of the message: the HTTP status code and,
	// when the response body has one, GitHub's error message.
	status string
	msg    string
}

func (e *APIError) Error() string { return e.msg }

// withContext returns a copy of e whose message describes the failed request
// with errContext instead.
func (e *APIError) withContext(errContext string) *APIError {
	return &APIError{StatusCode: e.StatusCode, status: e.status, msg: errContext + ": " + e.status}
}

// IsNotFound reports whether err is (or wraps) a GitHub API error with HTTP 404.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound
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

	status := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if body.Message != "" {
		status += ": " + body.Message
	}
	return &APIError{StatusCode: resp.StatusCode, status: status, msg: errContext + ": " + status}
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
	r, err := c.repository(ctx, owner, repo)
	if err != nil {
		return false, err
	}
	return r.Archived, nil
}

// RepoExists reports whether the repository exists and is visible to the
// client's credentials. GitHub answers HTTP 404, not 403, for a private
// repository the credentials cannot see, so a missing repository and an
// inaccessible one are both reported as (false, nil); other API failures are
// returned as errors. Results are cached and shared with IsArchived.
func (c *Client) RepoExists(ctx context.Context, owner, repo string) (bool, error) {
	_, err := c.repository(ctx, owner, repo)
	if err == nil {
		return true, nil
	}
	if IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// repository fetches the repository metadata. Results are cached.
func (c *Client) repository(ctx context.Context, owner, repo string) (*repoResponse, error) {
	key := fmt.Sprintf("%s/%s", owner, repo)
	if v, ok := c.repoCache.Load(key); ok {
		entry := v.(repoCacheEntry)
		return entry.repo, entry.err
	}

	v, err, _ := c.repoFlight.Do(key, func() (any, error) {
		r, err := c.fetchRepository(ctx, owner, repo)
		c.repoCache.Store(key, repoCacheEntry{repo: r, err: err})
		return r, err
	})
	if err != nil {
		return nil, err
	}
	return v.(*repoResponse), nil
}

func (c *Client) fetchRepository(ctx context.Context, owner, repo string) (*repoResponse, error) {
	path := repoPath(owner, repo, "")
	var r repoResponse
	if err := c.doGet(ctx, path, &r, fmt.Sprintf("failed to fetch repository metadata for %s/%s", owner, repo)); err != nil {
		return nil, err
	}
	return &r, nil
}

// FetchActionFile fetches and parses the action.yml (or action.yaml) for a
// remote action at the given ref. subPath is the subdirectory within the repo
// (e.g., "ec2/deploy" for "actions/aws/ec2/deploy@ref"); pass "" for root-level
// actions. Results are cached.
func (c *Client) FetchActionFile(ctx context.Context, owner, repo, subPath, ref string) (*ast.File, error) {
	key := actionKey(owner, repo, subPath, ref)
	if v, ok := c.actionFileCache.Load(key); ok {
		entry := v.(actionFileCacheEntry)
		return entry.file, entry.err
	}

	v, err, _ := c.actionFileFlight.Do(key, func() (any, error) {
		f, err := c.fetchActionFile(ctx, owner, repo, subPath, ref)
		c.actionFileCache.Store(key, actionFileCacheEntry{file: f, err: err})
		return f, err
	})
	if err != nil {
		return nil, err
	}
	return v.(*ast.File), nil
}

// actionKey returns the action reference as written in a "uses" value:
// "owner/repo@ref", or "owner/repo/subPath@ref" for an action in a
// subdirectory.
func actionKey(owner, repo, subPath, ref string) string {
	if subPath != "" {
		return fmt.Sprintf("%s/%s/%s@%s", owner, repo, subPath, ref)
	}
	return fmt.Sprintf("%s/%s@%s", owner, repo, ref)
}

func (c *Client) fetchActionFile(ctx context.Context, owner, repo, subPath, ref string) (*ast.File, error) {
	key := actionKey(owner, repo, subPath, ref)
	f, err := c.fetchContent(ctx, owner, repo, subPath, ref, "action.yml", key)
	if err == nil {
		return f, nil
	}
	// Only fall back to action.yaml when action.yml does not exist (404).
	// Other errors (500, 429, network, etc.) should propagate immediately.
	if !IsNotFound(err) {
		return nil, err
	}
	// Errors about action.yaml also say that action.yml was not found, so
	// that they do not suggest action.yml was never looked for.
	f, err = c.fetchContent(ctx, owner, repo, subPath, ref, "action.yaml", key+" (action.yml was not found)")
	var ae *APIError
	if errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound {
		return nil, ae.withContext(fmt.Sprintf("failed to fetch action.yml or action.yaml for %s", key))
	}
	return f, err
}

// fetchContent fetches and parses filename in the action's directory. subject
// names the action in error messages.
func (c *Client) fetchContent(ctx context.Context, owner, repo, subPath, ref, filename, subject string) (*ast.File, error) {
	contentPath := filename
	if subPath != "" {
		contentPath = subPath + "/" + filename
	}
	apiPath := repoPath(owner, repo, "/contents/"+escapeSegments(contentPath)+"?"+url.Values{"ref": {ref}}.Encode())
	var resp contentResponse
	if err := c.doGet(ctx, apiPath, &resp, fmt.Sprintf("failed to fetch %s for %s", filename, subject)); err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s for %s: %w", filename, subject, err)
	}

	f, err := yamlparser.ParseBytes(decoded, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s for %s: %w", filename, subject, err)
	}
	return f, nil
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
			reachable := isReachableStatus(status)
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
	path := repoPath(owner, repo, "/tags")
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
	path := repoPath(owner, repo, "/branches")
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
	path := repoPath(owner, repo, "/compare/"+escapeSegments(base)+"..."+url.PathEscape(sha)+"?per_page=1")
	errContext := fmt.Sprintf("failed to compare %s...%s on %s/%s", base, sha, owner, repo)
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", requestError(errContext, err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", requestError(errContext, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 404 means the commits share no common history (not reachable from this branch).
	// This is also returned if the repo was deleted between listBranches and this call,
	// but that race is unavoidable with the compare API.
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", c.apiError(resp, errContext)
	}

	var cr compareResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", fmt.Errorf("%s: %w", errContext, err)
	}
	return cr.Status, nil
}

func (c *Client) doGetPaginated(ctx context.Context, path string, result any, errContext string) (string, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", requestError(errContext, err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", requestError(errContext, err)
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
