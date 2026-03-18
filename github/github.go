package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const defaultBaseURL = "https://api.github.com"

type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	cache      sync.Map // key: "owner/repo@tag", value: cacheEntry
	flight     singleflight.Group
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
		token:      os.Getenv("GITHUB_TOKEN"),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// gitRef represents the response from both the git refs API and git tags API.
type gitRef struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
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

func (c *Client) getRef(ctx context.Context, owner, repo, tag string) (*gitRef, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/ref/tags/%s", c.baseURL, owner, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp, fmt.Sprintf("failed to resolve tag %q on %s/%s", tag, owner, repo))
	}

	var ref gitRef
	if err := json.NewDecoder(resp.Body).Decode(&ref); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &ref, nil
}

func (c *Client) dereferenceTag(ctx context.Context, owner, repo, tagSHA string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/tags/%s", c.baseURL, owner, repo, tagSHA)
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
		return "", apiError(resp, fmt.Sprintf("failed to dereference tag object %q on %s/%s", tagSHA, owner, repo))
	}

	var ref gitRef
	if err := json.NewDecoder(resp.Body).Decode(&ref); err != nil {
		return "", fmt.Errorf("failed to decode tag object: %w", err)
	}

	if ref.Object.Type != "commit" {
		return "", fmt.Errorf("expected tag to point to commit, got %q", ref.Object.Type)
	}
	return ref.Object.SHA, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// apiError builds an error from a non-200 GitHub API response,
// including the error message from the response body when available.
func apiError(resp *http.Response, context string) error {
	var body struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)

	if body.Message != "" {
		return fmt.Errorf("%s: HTTP %d: %s", context, resp.StatusCode, body.Message)
	}
	return fmt.Errorf("%s: HTTP %d", context, resp.StatusCode)
}
