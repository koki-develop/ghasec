package e2e_test

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"text/template"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata
var testdata embed.FS

var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "ghasec-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	bin := filepath.Join(tmp, "ghasec")
	cmd := exec.Command("go", "build", "-o", bin, "..")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(tmp)
		fmt.Fprintf(os.Stderr, "failed to build ghasec: %v\n", err)
		os.Exit(1)
	}
	binaryPath = bin

	// Capture binary version for template expansion in SARIF tests.
	verCmd := exec.Command(bin, "--version")
	verOut, err := verCmd.Output()
	if err == nil {
		// Output is "ghasec version <ver>\n"
		binaryVersion = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(verOut)), "ghasec version "))
	}

	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

type expected struct {
	ExitCode int    `yaml:"exit_code"`
	Stdout   string `yaml:"stdout"`
	Stderr   string `yaml:"stderr"`
}

type testCase struct {
	Args      string         `yaml:"args"`
	Workflows []testWorkflow `yaml:"workflows"`
	Actions   []testAction   `yaml:"actions"`
	Expected  expected       `yaml:"expected"`
}

type testAction struct {
	Name    string `yaml:"name"`
	Content string `yaml:"content"`
}

type testWorkflow struct {
	Name    string `yaml:"name"`
	Content string `yaml:"content"`
}

type templateData struct {
	Dir     string
	Version string
}

var binaryVersion string

func TestE2E(t *testing.T) {
	err := fs.WalkDir(testdata, "testdata", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}
		// path is relative to embed root, e.g. "testdata/subdir/foo.yml"
		rel := strings.TrimPrefix(path, "testdata/")
		name := strings.TrimSuffix(rel, ".yml")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runTestCase(t, name)
		})
		return nil
	})
	require.NoError(t, err)
}

// extraEnvVars maps test case names to additional environment variables.
var extraEnvVars = map[string][]string{
	"offline-warning-disabled": {"GHASEC_DISABLE_OFFLINE_WARNING="},
}

// suppressOfflineWarning lists test cases that do NOT want the offline warning
// suppressed by default (i.e., they intentionally test offline-warning behavior).
var suppressOfflineWarningExclude = map[string]bool{
	"offline-warning":                          true,
	"github-actions-format/no-offline-warning": true,
	"markdown-format/online-rules-skipped":     true,
}

// mockGitHubTags maps test case names to their mock GitHub API tag data.
// Key format: "/repos/{owner}/{repo}/git/ref/tags/{tag}".
var mockGitHubTags = map[string]map[string]mockGitRef{}

type mockGitRef struct {
	Ref    string        `json:"ref"`
	Object mockGitObject `json:"object"`
}

type mockGitObject struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type mockRepoTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

// mockGitHubHandler maps test case names to custom HTTP handlers for the mock
// GitHub API server. Use this for rules that need multi-endpoint mocking
// (tag listing, branch listing, compare, etc.) beyond simple tag resolution.
// Takes precedence over mockGitHubTags when both match.
var mockGitHubHandler = map[string]http.HandlerFunc{
	"archived-action":                                  archivedActionHandler,
	"mismatched-sha-tag":                               mismatchedSHATagHandler,
	"impostor-commit":                                  impostorCommitHandler,
	"unpinned-transitive-action":                       unpinnedTransitiveActionHandler,
	"github-actions-format/unpinned-transitive-action": unpinnedTransitiveActionHandler,
	"markdown-format/unpinned-transitive-action":       unpinnedTransitiveActionHandler,
	"sarif-format/unpinned-transitive-action":          unpinnedTransitiveActionHandler,
}

// nodeActionContent is a base64-encoded action.yml for a non-composite (node20)
// action. Used by mock handlers to satisfy unpinned-transitive-action API calls
// without producing errors.
var nodeActionContent = base64.StdEncoding.EncodeToString([]byte("name: mock\nruns:\n  using: node20\n  main: index.js\n"))

func archivedActionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/repos/archived-org/archived-repo":
		_ = json.NewEncoder(w).Encode(map[string]any{"archived": true})
	case "/repos/active-org/active-repo":
		_ = json.NewEncoder(w).Encode(map[string]any{"archived": false})
	case "/repos/evil/action":
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	}
}

func mismatchedSHATagHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	const validSHA = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"

	switch r.URL.Path {
	// Tag resolution for mismatched-sha-tag
	case "/repos/actions/checkout/git/ref/tags/v4":
		_ = json.NewEncoder(w).Encode(mockGitRef{
			Ref:    "refs/tags/v4",
			Object: mockGitObject{Type: "commit", SHA: validSHA},
		})
	// Tag listing — needed because impostor-commit rule also runs during mismatched-sha-tag tests
	case "/repos/actions/checkout/tags":
		_ = json.NewEncoder(w).Encode([]mockRepoTag{
			{Name: "v4", Commit: struct {
				SHA string `json:"sha"`
			}{SHA: validSHA}},
		})
	// Repo metadata — needed because archived-action rule also runs during mismatched-sha-tag tests
	case "/repos/actions/checkout":
		_ = json.NewEncoder(w).Encode(map[string]any{"archived": false})
	default:
		// Contents API — needed because unpinned-transitive-action rule also runs
		if strings.Contains(r.URL.Path, "/contents/action.y") {
			_ = json.NewEncoder(w).Encode(map[string]string{"content": nodeActionContent})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	}
}

func impostorCommitHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	const (
		reachableSHA  = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
		impostorSHA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		taggedSHA     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		annotatedSHA  = "cccccccccccccccccccccccccccccccccccccccc"
		tagObjectSHA  = "dddddddddddddddddddddddddddddddddddddd"
		nonDefaultSHA = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	)

	switch r.URL.Path {
	// ===== actions/checkout =====
	case "/repos/actions/checkout/tags":
		_ = json.NewEncoder(w).Encode([]mockRepoTag{
			{Name: "v4", Commit: struct {
				SHA string `json:"sha"`
			}{SHA: taggedSHA}},
		})
	case "/repos/actions/checkout/git/ref/tags/v4":
		_ = json.NewEncoder(w).Encode(mockGitRef{
			Ref: "refs/tags/v4", Object: mockGitObject{Type: "commit", SHA: taggedSHA},
		})

	// ===== actions/setup-go (annotated tag — /tags API returns resolved commit SHA) =====
	case "/repos/actions/setup-go/tags":
		_ = json.NewEncoder(w).Encode([]mockRepoTag{
			{Name: "v5", Commit: struct {
				SHA string `json:"sha"`
			}{SHA: annotatedSHA}},
		})
	case "/repos/actions/setup-go/git/ref/tags/v5":
		_ = json.NewEncoder(w).Encode(mockGitRef{
			Ref: "refs/tags/v5", Object: mockGitObject{Type: "tag", SHA: tagObjectSHA},
		})
	case "/repos/actions/setup-go/git/tags/" + tagObjectSHA:
		_ = json.NewEncoder(w).Encode(mockGitRef{
			Object: mockGitObject{Type: "commit", SHA: annotatedSHA},
		})

	// ===== actions/setup-node =====
	case "/repos/actions/setup-node/tags":
		_ = json.NewEncoder(w).Encode([]mockRepoTag{})
	case "/repos/actions/setup-node/git/ref/tags/v1":
		_ = json.NewEncoder(w).Encode(mockGitRef{
			Ref: "refs/tags/v1", Object: mockGitObject{Type: "commit", SHA: impostorSHA},
		})
	case "/repos/actions/setup-node/git/ref/tags/v2":
		_ = json.NewEncoder(w).Encode(mockGitRef{
			Ref: "refs/tags/v2", Object: mockGitObject{Type: "commit", SHA: reachableSHA},
		})
	case "/repos/actions/setup-node/branches":
		_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "main"}})
	case "/repos/actions/setup-node/compare/main..." + reachableSHA:
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "behind"})
	case "/repos/actions/setup-node/compare/main..." + impostorSHA:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})

	// ===== actions/cache (non-default branch) =====
	case "/repos/actions/cache/tags":
		_ = json.NewEncoder(w).Encode([]mockRepoTag{})
	case "/repos/actions/cache/git/ref/tags/v1":
		_ = json.NewEncoder(w).Encode(mockGitRef{
			Ref: "refs/tags/v1", Object: mockGitObject{Type: "commit", SHA: nonDefaultSHA},
		})
	case "/repos/actions/cache/branches":
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"name": "main"},
			{"name": "releases/v2"},
		})
	case "/repos/actions/cache/compare/main..." + nonDefaultSHA:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	case "/repos/actions/cache/compare/releases/v2..." + nonDefaultSHA:
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "behind"})

	// ===== evil/action (API failure) =====
	case "/repos/evil/action/tags":
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
		return

	// Repo metadata — needed because archived-action rule also runs during impostor-commit tests
	case "/repos/actions/checkout",
		"/repos/actions/setup-go",
		"/repos/actions/setup-node",
		"/repos/actions/cache",
		"/repos/evil/action":
		_ = json.NewEncoder(w).Encode(map[string]any{"archived": false})

	default:
		// Contents API — needed because unpinned-transitive-action rule also runs
		if strings.Contains(r.URL.Path, "/contents/action.y") {
			// evil/action returns 500 for all endpoints
			if strings.Contains(r.URL.Path, "evil/action") {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"content": nodeActionContent})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	}
}

func unpinnedTransitiveActionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	const (
		shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		shaC = "cccccccccccccccccccccccccccccccccccccccc"
	)

	encodeAction := func(content string) map[string]string {
		return map[string]string{"content": base64.StdEncoding.EncodeToString([]byte(content))}
	}

	// Contents API (action.yml files)
	if strings.Contains(r.URL.Path, "/contents/action.y") {
		// evil/action returns 500 for all endpoints including contents
		if strings.Contains(r.URL.Path, "evil/") {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
			return
		}
		ref := r.URL.Query().Get("ref")
		// Extract repo: /repos/{owner}/{repo}/contents/...
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 5 {
			repoPath := parts[2] + "/" + parts[3]
			key := repoPath + "@" + ref

			actions := map[string]string{
				// valid-all-pinned: A(sha) -> B(sha) -> C(node20)
				"owner/action-a@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-b@" + shaB + "\n",
				"owner/action-b@" + shaB: "name: B\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-c@" + shaC + "\n",
				"owner/action-c@" + shaC: "name: C\nruns:\n  using: node20\n  main: index.js\n",

				// valid-no-steps
				"owner/node-action@" + shaA: "name: Node\nruns:\n  using: node20\n  main: index.js\n",

				// valid-local-action
				"owner/local-ref-action@" + shaA: "name: Local\nruns:\n  using: composite\n  steps:\n    - uses: ./local\n",

				// valid-docker-digest
				"owner/docker-digest-action@" + shaA: "name: Docker\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n",

				// unpinned-depth-1
				"owner/unpinned-depth1@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n",

				// unpinned-depth-2: A -> B(sha) -> C@v1
				"owner/unpinned-depth2@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/depth2-b@" + shaB + "\n",
				"owner/depth2-b@" + shaB:        "name: B\nruns:\n  using: composite\n  steps:\n    - uses: other/action-c@v1\n",

				// unpinned-depth-3: A -> B(sha) -> C(sha) -> D@main
				"owner/unpinned-depth3@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/depth3-b@" + shaB + "\n",
				"owner/depth3-b@" + shaB:        "name: B\nruns:\n  using: composite\n  steps:\n    - uses: owner/depth3-c@" + shaC + "\n",
				"owner/depth3-c@" + shaC:        "name: C\nruns:\n  using: composite\n  steps:\n    - uses: other/action-d@main\n",

				// unpinned-docker-no-digest
				"owner/docker-unpinned@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine:latest\n",

				// unpinned-multiple-steps
				"owner/multi-unpinned@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v1\n    - uses: other/action-c@v2\n",

				// unpinned-mixed-steps
				"owner/mixed-steps@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-b@" + shaB + "\n    - uses: other/action-c@v1\n",
				// action-b used by mixed-steps is node20 (no further transitive deps)

				// unpinned-ref-empty
				"owner/ref-empty@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/no-ref-action\n",

				// unpinned-multiple-workflow-steps
				"owner/multi-wf-a@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v1\n",
				"owner/multi-wf-c@" + shaC: "name: C\nruns:\n  using: composite\n  steps:\n    - uses: other/action-d@v2\n",

				// circular-reference
				"owner/circular-a@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/circular-b@" + shaB + "\n",
				"owner/circular-b@" + shaB: "name: B\nruns:\n  using: composite\n  steps:\n    - uses: owner/circular-a@" + shaA + "\n",

				// stop-at-unpinned
				"owner/stop-at-unpinned@" + shaA: "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n",
			}

			if content, ok := actions[key]; ok {
				_ = json.NewEncoder(w).Encode(encodeAction(content))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		return
	}

	// Repo metadata (for archived-action rule)
	if strings.Count(r.URL.Path, "/") == 3 && strings.HasPrefix(r.URL.Path, "/repos/") && !strings.HasSuffix(r.URL.Path, "/tags") && !strings.HasSuffix(r.URL.Path, "/branches") {
		if strings.Contains(r.URL.Path, "evil/") {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"archived": false})
		return
	}

	// Tags listing (for impostor-commit rule) — return tag matching each known SHA
	if strings.HasSuffix(r.URL.Path, "/tags") {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 4 {
			repoKey := parts[2] + "/" + parts[3]
			knownRepoSHAs := map[string]string{
				"owner/action-a":             shaA,
				"owner/action-b":             shaB,
				"owner/action-c":             shaC,
				"owner/node-action":          shaA,
				"owner/local-ref-action":     shaA,
				"owner/docker-digest-action": shaA,
				"owner/unpinned-depth1":      shaA,
				"owner/unpinned-depth2":      shaA,
				"owner/depth2-b":             shaB,
				"owner/unpinned-depth3":      shaA,
				"owner/depth3-b":             shaB,
				"owner/depth3-c":             shaC,
				"owner/docker-unpinned":      shaA,
				"owner/multi-unpinned":       shaA,
				"owner/mixed-steps":          shaA,
				"owner/ref-empty":            shaA,
				"owner/multi-wf-a":           shaA,
				"owner/multi-wf-c":           shaC,
				"owner/circular-a":           shaA,
				"owner/circular-b":           shaB,
				"owner/stop-at-unpinned":     shaA,
			}
			if sha, ok := knownRepoSHAs[repoKey]; ok {
				_ = json.NewEncoder(w).Encode([]mockRepoTag{{Name: "v1", Commit: struct {
					SHA string `json:"sha"`
				}{SHA: sha}}})
				return
			}
		}
		if strings.Contains(r.URL.Path, "evil/") {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
			return
		}
		_ = json.NewEncoder(w).Encode([]mockRepoTag{})
		return
	}

	// Branches (for impostor-commit rule)
	if strings.HasSuffix(r.URL.Path, "/branches") {
		_ = json.NewEncoder(w).Encode([]map[string]string{})
		return
	}

	// API failure for evil/action
	if strings.Contains(r.URL.Path, "evil/") {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Internal Server Error"})
		return
	}

	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
}

func runTestCase(t *testing.T, name string) {
	t.Helper()

	tc := loadTestCase(t, name)

	tmpDir := t.TempDir()
	files := writeWorkflows(t, tc.Workflows, tmpDir)
	actionFiles := writeActions(t, tc.Actions, tmpDir)
	files = append(files, actionFiles...)
	sort.Strings(files)

	var extraArgs []string
	if tc.Args != "" {
		extraArgs = strings.Fields(tc.Args)
	}

	var extraEnv []string
	if handler, ok := lookupTestConfig(mockGitHubHandler, name); ok {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		extraEnv = append(extraEnv, "GHASEC_GITHUB_API_URL="+srv.URL)
	} else if tags, ok := lookupTestConfig(mockGitHubTags, name); ok {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ref, ok := tags[r.URL.Path]
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ref)
		}))
		t.Cleanup(srv.Close)
		extraEnv = append(extraEnv, "GHASEC_GITHUB_API_URL="+srv.URL)
	}
	if envs, ok := lookupTestConfig(extraEnvVars, name); ok {
		extraEnv = append(extraEnv, envs...)
	}
	if _, excluded := lookupTestConfig(suppressOfflineWarningExclude, name); !excluded {
		extraEnv = append(extraEnv, "GHASEC_DISABLE_OFFLINE_WARNING=")
	}
	extraEnv = append(extraEnv, "GHASEC_DISABLE_UPDATE_CHECK=")

	stdout, stderr, exitCode := runGhasec(t, files, extraArgs, extraEnv...)

	exp := tc.Expected
	exp.Stdout = expandTemplate(t, exp.Stdout, tmpDir)
	exp.Stderr = expandTemplate(t, exp.Stderr, tmpDir)

	assert.Equal(t, exp.ExitCode, exitCode, "exit code mismatch")
	assert.Equal(t, exp.Stdout, stdout, "stdout mismatch")
	assert.Equal(t, exp.Stderr, stderr, "stderr mismatch")
}

func writeWorkflows(t *testing.T, workflows []testWorkflow, tmpDir string) []string {
	t.Helper()

	var files []string
	for _, w := range workflows {
		dst := filepath.Join(tmpDir, w.Name)
		require.NoError(t, os.WriteFile(dst, []byte(w.Content), 0o644))
		files = append(files, dst)
	}
	sort.Strings(files)
	return files
}

func writeActions(t *testing.T, actions []testAction, tmpDir string) []string {
	t.Helper()
	var files []string
	for _, a := range actions {
		dst := filepath.Join(tmpDir, a.Name)
		dir := filepath.Dir(dst)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(dst, []byte(a.Content), 0o644))
		files = append(files, dst)
	}
	sort.Strings(files)
	return files
}

func runGhasec(t *testing.T, files []string, extraArgs []string, extraEnv ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	args := make([]string, 0, len(extraArgs)+len(files))
	args = append(args, extraArgs...)
	args = append(args, files...)
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=")
	cmd.Env = append(cmd.Env, extraEnv...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run ghasec: %v", err)
		}
	}

	return stdoutBuf.String(), stderrBuf.String(), exitCode
}

func loadTestCase(t *testing.T, name string) testCase {
	t.Helper()

	data, err := testdata.ReadFile(filepath.Join("testdata", name+".yml"))
	require.NoError(t, err)

	var tc testCase
	require.NoError(t, yaml.Unmarshal(data, &tc))

	return tc
}

// lookupTestConfig checks for an exact match on the test name, then falls back
// to matching the first path segment (directory name). This allows per-directory
// configuration (e.g., all tests under "mismatched-sha-tag/" share the same
// CLI args) without duplicating map entries.
func lookupTestConfig[V any](m map[string]V, name string) (V, bool) {
	if v, ok := m[name]; ok {
		return v, true
	}
	if dir, _, ok := strings.Cut(name, "/"); ok {
		if v, ok := m[dir]; ok {
			return v, true
		}
	}
	var zero V
	return zero, false
}

func TestE2E_NoWorkflowFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := exec.Command(binaryPath)
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "NO_COLOR=", "GHASEC_DISABLE_OFFLINE_WARNING=")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	require.Error(t, err)

	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Empty(t, stdoutBuf.String())
	assert.Equal(t, "error: no files found\n", stderrBuf.String())
}

func TestE2E_DirectoryArgument(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := exec.Command(binaryPath, tmpDir)
	cmd.Env = append(os.Environ(), "NO_COLOR=", "GHASEC_DISABLE_OFFLINE_WARNING=")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	require.Error(t, err)

	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Empty(t, stdoutBuf.String())
	assert.Equal(t, fmt.Sprintf("error: %s is a directory; specify files directly\n", tmpDir), stderrBuf.String())
}

func TestE2E_AutoDiscoverWithActions(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte("on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: actions/checkout@v6\n        with:\n          persist-credentials: false\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "action.yml"), []byte("name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v6\n      with:\n        persist-credentials: false\n"), 0o644))

	cmd := exec.Command(binaryPath)
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "NO_COLOR=", "GHASEC_DISABLE_OFFLINE_WARNING=")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	require.Error(t, err)
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, stderrBuf.String(), "✗ 2 errors found in 2 of 2 files")
}

func TestE2E_InvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflowDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte("on: push\n"), 0o644))

	cmd := exec.Command(binaryPath, "--format", "invalid")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "NO_COLOR=", "GHASEC_DISABLE_OFFLINE_WARNING=")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	require.Error(t, err)

	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Empty(t, stdoutBuf.String())
	assert.Equal(t, "error: invalid argument \"invalid\" for \"--format\" flag: unknown format \"invalid\"; must be \"default\", \"github-actions\", \"markdown\", or \"sarif\"\n", stderrBuf.String())
}

func expandTemplate(t *testing.T, text, tmpDir string) string {
	t.Helper()

	if text == "" {
		return ""
	}

	tmpl, err := template.New("").Parse(text)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, tmpl.Execute(&buf, templateData{Dir: tmpDir, Version: binaryVersion}))
	return buf.String()
}
