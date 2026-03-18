package e2e_test

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

type templateData struct {
	Dir string
}

func TestE2E(t *testing.T) {
	entries, err := testdata.ReadDir("testdata")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runTestCase(t, name)
		})
	}
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

	tmpDir := t.TempDir()
	files := writeWorkflows(t, name, tmpDir)

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

	stdout, stderr, exitCode := runGhasec(t, files, extraEnv...)

	exp := loadExpected(t, name, tmpDir)
	assert.Equal(t, exp.ExitCode, exitCode, "exit code mismatch")
	assert.Equal(t, exp.Stdout, stdout, "stdout mismatch")
	assert.Equal(t, exp.Stderr, stderr, "stderr mismatch")
}

func writeWorkflows(t *testing.T, name, tmpDir string) []string {
	t.Helper()

	workflowsDir := filepath.Join("testdata", name, "workflows")
	entries, err := testdata.ReadDir(workflowsDir)
	require.NoError(t, err)

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := testdata.ReadFile(filepath.Join(workflowsDir, entry.Name()))
		require.NoError(t, err)

		dst := filepath.Join(tmpDir, entry.Name())
		require.NoError(t, os.WriteFile(dst, data, 0o644))
		files = append(files, dst)
	}
	sort.Strings(files)
	return files
}

func runGhasec(t *testing.T, files []string, extraEnv ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(binaryPath, files...)
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

func loadExpected(t *testing.T, name, tmpDir string) expected {
	t.Helper()

	data, err := testdata.ReadFile(filepath.Join("testdata", name, "expected.yml"))
	require.NoError(t, err)

	var exp expected
	require.NoError(t, yaml.Unmarshal(data, &exp))

	exp.Stdout = expandTemplate(t, exp.Stdout, tmpDir)
	exp.Stderr = expandTemplate(t, exp.Stderr, tmpDir)

	return exp
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
