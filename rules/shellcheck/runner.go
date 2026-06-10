package shellcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Comment is a single shellcheck finding (subset of the json1 schema).
type Comment struct {
	File      string
	Line      int
	EndLine   int
	Column    int
	EndColumn int
	Level     string
	Code      int
	Message   string
}

// Runner runs shellcheck against (masked) shell scripts and returns its
// findings. It is abstracted as an interface so the rule can be tested with a
// mock and so the missing-binary case is handled uniformly.
type Runner interface {
	// RunBatch analyzes scripts with the given shell ("bash" or "sh") in a single
	// shellcheck invocation and returns the findings per script, indexed parallel
	// to scripts. Batching amortizes shellcheck's process-startup cost, which
	// dominates runtime when there are many run steps. Returns an error only for
	// genuine failures (shellcheck could not process the input); finding issues in
	// the scripts is not an error.
	RunBatch(ctx context.Context, shell string, scripts []string) ([][]Comment, error)
	// Available reports whether the shellcheck binary was found.
	Available() bool
}

// errUnavailable is returned by execRunner.Run when shellcheck is not installed.
var errUnavailable = errors.New("shellcheck binary not found")

// execRunner runs the real shellcheck binary.
type execRunner struct {
	path string
}

// NewExecRunner locates the shellcheck binary on PATH. If it is not found, the
// returned Runner reports Available() == false and Run returns errUnavailable.
func NewExecRunner() Runner {
	path, err := exec.LookPath("shellcheck")
	if err != nil {
		return &execRunner{}
	}
	return &execRunner{path: path}
}

func (r *execRunner) Available() bool { return r.path != "" }

// scArgs are the shellcheck flags shared by every invocation. SC2154 (variable
// referenced but not assigned) is excluded: GitHub Actions defines variables
// outside the analyzed script (env: blocks, $GITHUB_ENV from prior steps,
// matrix, runner env), which shellcheck cannot see, so it is an unavoidable
// false positive in this context. shellcheck already suppresses it for all-caps
// names; -e covers lowercase ones too.
var scArgs = []string{"--norc", "-f", "json1", "-S", "info", "-e", "SC2154"}

// run executes shellcheck with the given args, feeding stdin (may be empty), and
// returns its decoded findings. Exit code 1 (issues found) is a normal result;
// exit code >= 2 means shellcheck could not process the input.
func (r *execRunner) run(ctx context.Context, stdin string, args ...string) ([]Comment, error) {
	cmd := exec.CommandContext(ctx, r.path, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("shellcheck failed (exit %d): %s", exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
			}
		} else {
			return nil, err
		}
	}
	return parseComments(stdout.Bytes())
}

// Run analyzes a single script via stdin. Retained for the single-script fast
// path (identical to the historical behavior) and for direct unit testing.
func (r *execRunner) Run(ctx context.Context, shell, script string) ([]Comment, error) {
	if r.path == "" {
		return nil, errUnavailable
	}
	args := append(append([]string{}, scArgs...), "-s", shell, "-")
	return r.run(ctx, script, args...)
}

// RunBatch analyzes multiple scripts. A single script takes the stdin fast path
// (byte-for-byte identical to Run). Two or more scripts are written to temp
// files and linted in one shellcheck invocation, so the per-process startup cost
// is paid once instead of once per script; findings are demultiplexed back to
// each script by the reported file path.
func (r *execRunner) RunBatch(ctx context.Context, shell string, scripts []string) ([][]Comment, error) {
	if r.path == "" {
		return nil, errUnavailable
	}
	if len(scripts) == 0 {
		return nil, nil
	}
	if len(scripts) == 1 {
		cs, err := r.Run(ctx, shell, scripts[0])
		if err != nil {
			return nil, err
		}
		return [][]Comment{cs}, nil
	}

	dir, err := os.MkdirTemp("", "ghasec-shellcheck-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	idxByPath := make(map[string]int, len(scripts))
	args := append(append([]string{}, scArgs...), "-s", shell)
	for i, s := range scripts {
		p := filepath.Join(dir, strconv.Itoa(i))
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			return nil, err
		}
		idxByPath[p] = i
		args = append(args, p)
	}

	comments, err := r.run(ctx, "", args...)
	if err != nil {
		return nil, err
	}

	out := make([][]Comment, len(scripts))
	for _, c := range comments {
		if idx, ok := idxByPath[c.File]; ok {
			out[idx] = append(out[idx], c)
		}
	}
	return out, nil
}

// parseComments decodes shellcheck json1 output into Comments.
func parseComments(data []byte) ([]Comment, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var out struct {
		Comments []Comment `json:"comments"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("failed to parse shellcheck output: %w", err)
	}
	return out.Comments, nil
}
