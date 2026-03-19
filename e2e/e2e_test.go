package e2e_test

import (
	"bytes"
	"embed"
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
	Workflows []testWorkflow `yaml:"workflows"`
	Expected  expected       `yaml:"expected"`
}

type testWorkflow struct {
	Name    string `yaml:"name"`
	Content string `yaml:"content"`
}

type templateData struct {
	Dir string
}

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

// extraCLIArgs maps test case names to additional CLI flags.
var extraCLIArgs = map[string][]string{
	"mismatched-sha-tag": {"--online"},
}

// extraEnvVars maps test case names to additional environment variables.
var extraEnvVars = map[string][]string{
	"offline-warning-disabled": {"GHASEC_DISABLE_OFFLINE_WARNING="},
}

// suppressOfflineWarning lists test cases that do NOT want the offline warning
// suppressed by default (i.e., they intentionally test offline-warning behavior).
var suppressOfflineWarningExclude = map[string]bool{
	"offline-warning": true,
}

// mockGitHubTags maps test case names to their mock GitHub API tag data.
// Key format: "/repos/{owner}/{repo}/git/ref/tags/{tag}".
var mockGitHubTags = map[string]map[string]mockGitRef{
	"mismatched-sha-tag": {
		"/repos/actions/checkout/git/ref/tags/v4": {
			Ref: "refs/tags/v4",
			Object: mockGitObject{
				Type: "commit",
				SHA:  "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
			},
		},
	},
}

type mockGitRef struct {
	Ref    string        `json:"ref"`
	Object mockGitObject `json:"object"`
}

type mockGitObject struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

func runTestCase(t *testing.T, name string) {
	t.Helper()

	tc := loadTestCase(t, name)

	tmpDir := t.TempDir()
	files := writeWorkflows(t, tc.Workflows, tmpDir)

	var extraArgs []string
	if args, ok := extraCLIArgs[name]; ok {
		extraArgs = args
	}

	var extraEnv []string
	if tags, ok := mockGitHubTags[name]; ok {
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
	if envs, ok := extraEnvVars[name]; ok {
		extraEnv = append(extraEnv, envs...)
	}
	if !suppressOfflineWarningExclude[name] {
		extraEnv = append(extraEnv, "GHASEC_DISABLE_OFFLINE_WARNING=")
	}

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

func expandTemplate(t *testing.T, text, tmpDir string) string {
	t.Helper()

	if text == "" {
		return ""
	}

	tmpl, err := template.New("").Parse(text)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, tmpl.Execute(&buf, templateData{Dir: tmpDir}))
	return buf.String()
}
