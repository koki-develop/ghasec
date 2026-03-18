package e2e_test

import (
	"bytes"
	"embed"
	"fmt"
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
		os.RemoveAll(tmp)
		fmt.Fprintf(os.Stderr, "failed to build ghasec: %v\n", err)
		os.Exit(1)
	}
	binaryPath = bin

	code := m.Run()
	os.RemoveAll(tmp)
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

func runTestCase(t *testing.T, name string) {
	t.Helper()

	tmpDir := t.TempDir()
	files := writeWorkflows(t, name, tmpDir)

	stdout, stderr, exitCode := runGhasec(t, files)

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

func runGhasec(t *testing.T, files []string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(binaryPath, files...)
	cmd.Env = append(os.Environ(), "NO_COLOR=")

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
