// Command gen fills the `expected:` block of shellcheck E2E testdata files by
// running the real ghasec binary, so expected output stays in sync with the
// installed shellcheck version. It lives under e2e/_gen (a "_"-prefixed dir Go
// tooling ignores) and is a development aid, not part of the test suite.
//
// Usage (from repo root):
//
//	go run ./e2e/_gen
//
// For each *.yml under e2e/testdata/shellcheck, it parses the inputs exactly as
// the test runner does, runs ghasec, and rewrites the file's `expected:` block
// with the captured exit code / stdout / stderr (temp dir replaced by {{.Dir}},
// version by {{.Version}}).
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

type spec struct {
	Args      string            `yaml:"args"`
	Env       map[string]string `yaml:"env"`
	Workflows []file            `yaml:"workflows"`
	Actions   []file            `yaml:"actions"`
}

type file struct {
	Name    string `yaml:"name"`
	Content string `yaml:"content"`
}

func main() {
	root, err := os.Getwd()
	must(err)
	testdataDir := filepath.Join(root, "e2e", "testdata", "shellcheck")

	tmp, err := os.MkdirTemp("", "ghasec-gen-*")
	must(err)
	defer os.RemoveAll(tmp)
	bin := filepath.Join(tmp, "ghasec")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	must(build.Run())

	verOut, _ := exec.Command(bin, "--version").Output()
	version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(verOut)), "ghasec version "))

	var files []string
	if args := os.Args[1:]; len(args) > 0 {
		// Explicit file paths to (re)generate, e.g. existing testdata affected
		// by adding the shellcheck rule. Online tests must NOT be passed here.
		for _, a := range args {
			abs, err := filepath.Abs(a)
			must(err)
			files = append(files, abs)
		}
	} else {
		must(filepath.Walk(testdataDir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && filepath.Ext(p) == ".yml" {
				files = append(files, p)
			}
			return nil
		}))
	}
	sort.Strings(files)

	for _, ymlPath := range files {
		raw, err := os.ReadFile(ymlPath)
		must(err)
		var sp spec
		must(yaml.Unmarshal(raw, &sp))

		exit, stdout, stderr := run(bin, sp)
		caseDir := filepath.Dir(ymlPath) // not used; placeholder
		_ = caseDir

		expected := buildExpected(exit, normalize(stdout, version), normalize(stderr, version))
		newRaw := replaceExpected(string(raw), expected)
		must(os.WriteFile(ymlPath, []byte(newRaw), 0o644))
		fmt.Printf("updated %s (exit=%d)\n", rel(testdataDir, ymlPath), exit)
	}
}

func run(bin string, sp spec) (int, string, string) {
	dir, err := os.MkdirTemp("", "ghasec-case-*")
	must(err)
	defer os.RemoveAll(dir)

	var paths []string
	writeAll := func(fs []file) {
		for _, f := range fs {
			dst := filepath.Join(dir, f.Name)
			must(os.MkdirAll(filepath.Dir(dst), 0o755))
			must(os.WriteFile(dst, []byte(f.Content), 0o644))
			paths = append(paths, dst)
		}
	}
	writeAll(sp.Workflows)
	writeAll(sp.Actions)
	sort.Strings(paths)

	var args []string
	if sp.Args != "" {
		args = append(args, strings.Fields(sp.Args)...)
	}
	args = append(args, paths...)

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=", "GHASEC_DISABLE_OFFLINE_WARNING=", "GHASEC_DISABLE_UPDATE_CHECK=")
	envKeys := make([]string, 0, len(sp.Env))
	for k := range sp.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		cmd.Env = append(cmd.Env, k+"="+sp.Env[k])
	}

	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	exit := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			panic(err)
		}
	}
	// Escape literal Go-template delimiters in the captured output FIRST (the
	// shell source may contain "${{ ... }}"), then introduce the intentional
	// {{.Dir}} template placeholder. The test runner expands expected output
	// with text/template, so a literal "{{" must be emitted as `{{"{{" }}`.
	prep := func(s string) string {
		s = strings.ReplaceAll(s, "{{", `{{"{{" }}`)
		s = strings.ReplaceAll(s, dir, "{{.Dir}}")
		return s
	}
	return exit, prep(so.String()), prep(se.String())
}

func normalize(s, version string) string {
	if version != "" {
		s = strings.ReplaceAll(s, version, "{{.Version}}")
	}
	return s
}

func buildExpected(exit int, stdout, stderr string) string {
	var b strings.Builder
	b.WriteString("expected:\n")
	fmt.Fprintf(&b, "  exit_code: %d\n", exit)
	b.WriteString("  stdout: " + yamlScalar(stdout, "  ") + "\n")
	b.WriteString("  stderr: " + yamlScalar(stderr, "  ") + "\n")
	return b.String()
}

// yamlScalar renders s as a YAML scalar value for a key at the given indent.
// Empty -> `""`. Otherwise a block scalar with chomping chosen to reproduce the
// exact trailing-newline count.
func yamlScalar(s, indent string) string {
	if s == "" {
		return `""`
	}
	trailing := len(s) - len(strings.TrimRight(s, "\n"))
	core := strings.TrimRight(s, "\n")
	body := indent + "  "
	indentLines := func(text string) string {
		lines := strings.Split(text, "\n")
		for i, ln := range lines {
			if ln == "" {
				lines[i] = ""
			} else {
				lines[i] = body + ln
			}
		}
		return strings.Join(lines, "\n")
	}
	switch {
	case trailing == 0:
		return "|-\n" + indentLines(core)
	case trailing == 1:
		return "|\n" + indentLines(core)
	default:
		// keep: append (trailing-1) blank lines after core
		blanks := strings.Repeat("\n", trailing-1)
		return "|+\n" + indentLines(core) + blanks
	}
}

// replaceExpected removes any existing top-level `expected:` block and appends
// the freshly built one, preserving the hand-authored input section verbatim.
func replaceExpected(raw, expected string) string {
	idx := indexTopLevel(raw, "expected:")
	if idx >= 0 {
		raw = raw[:idx]
	}
	if !strings.HasSuffix(raw, "\n") {
		raw += "\n"
	}
	// Ensure exactly one blank line is not required; keep tidy single newline.
	return strings.TrimRight(raw, "\n") + "\n" + expected
}

// indexTopLevel returns the byte index of a line that begins with key at column
// 0, or -1.
func indexTopLevel(raw, key string) int {
	if strings.HasPrefix(raw, key) {
		return 0
	}
	needle := "\n" + key
	if i := strings.Index(raw, needle); i >= 0 {
		return i + 1
	}
	return -1
}

func rel(base, p string) string {
	r, err := filepath.Rel(base, p)
	if err != nil {
		return p
	}
	return r
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
