package shellcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Comment is a single shellcheck finding (subset of the json1 schema).
type Comment struct {
	Line      int
	EndLine   int
	Column    int
	EndColumn int
	Level     string
	Code      int
	Message   string
}

// Runner runs shellcheck against a (masked) shell script and returns its
// findings. It is abstracted as an interface so the rule can be tested with a
// mock and so the missing-binary case is handled uniformly.
type Runner interface {
	// Run analyzes script with the given shell ("bash" or "sh") and returns the
	// findings. Returns an error only for genuine failures (shellcheck could not
	// process the input); finding issues in the script is not an error.
	Run(ctx context.Context, shell, script string) ([]Comment, error)
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

func (r *execRunner) Run(ctx context.Context, shell, script string) ([]Comment, error) {
	if r.path == "" {
		return nil, errUnavailable
	}
	cmd := exec.CommandContext(ctx, r.path, "--norc", "-f", "json1", "-S", "info", "-s", shell, "-")
	cmd.Stdin = strings.NewReader(script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Exit code 1 means shellcheck found issues — a normal result.
			// Exit code >= 2 means it could not process the input.
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("shellcheck failed (exit %d): %s", exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
			}
		} else {
			return nil, err
		}
	}

	return parseComments(stdout.Bytes())
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
