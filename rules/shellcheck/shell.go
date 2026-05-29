package shellcheck

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
)

// normalizeShell maps a GitHub Actions shell string to the value passed to
// shellcheck's -s flag, and reports whether the shell is one shellcheck can
// analyze. GitHub allows custom command forms such as "bash -e {0}" or
// "pwsh -Command {0}", so only the first whitespace-separated token is
// considered. Only bash and sh are supported; everything else (pwsh,
// powershell, python, cmd, custom commands, ...) returns ("", false).
func normalizeShell(raw string) (sh string, ok bool) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", false
	}
	switch fields[0] {
	case "bash", "sh":
		return fields[0], true
	default:
		return "", false
	}
}

// isWindowsOnly reports whether a runs-on node can be confidently determined to
// target Windows runners only (whose default shell is pwsh, not bash). It is
// deliberately conservative: anything ambiguous (expressions like
// ${{ matrix.os }}, arrays mixing OS labels, non-string nodes) returns false so
// the step is still analyzed as bash. Only an unambiguous Windows target
// returns true.
func isWindowsOnly(runsOn ast.Node) bool {
	switch v := runsOn.(type) {
	case *ast.StringNode:
		return labelIsWindows(v.Value)
	case *ast.LiteralNode:
		return labelIsWindows(v.Value.Value)
	case *ast.SequenceNode:
		hasWindows := false
		for _, el := range v.Values {
			s, ok := nodeString(el)
			if !ok {
				// Non-string / expression element: not confidently resolvable.
				return false
			}
			if isExpression(s) {
				return false
			}
			if labelIsWindows(s) {
				hasWindows = true
				continue
			}
			if labelIsNonWindowsOS(s) {
				return false
			}
			// Other labels (self-hosted, x64, custom, ...) are OS-neutral.
		}
		return hasWindows
	default:
		return false
	}
}

func nodeString(node ast.Node) (string, bool) {
	switch v := node.(type) {
	case *ast.StringNode:
		return v.Value, true
	case *ast.LiteralNode:
		return v.Value.Value, true
	}
	return "", false
}

func isExpression(s string) bool {
	return strings.Contains(s, "${{")
}

func labelIsWindows(s string) bool {
	if isExpression(s) {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "windows")
}

func labelIsNonWindowsOS(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{"ubuntu", "macos", "linux", "macos-", "darwin"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// resolveWorkflowTarget decides whether a workflow run step should be analyzed
// and returns the shellcheck -s value. effShell is the effective shell string
// resolved as step.shell → job defaults → workflow defaults; shellSpecified
// indicates whether any of those provided a value. runsOn is the job's runs-on
// node (may be nil). When no shell is specified, the step defaults to bash
// unless runs-on resolves to a Windows-only target (pwsh), in which case it is
// skipped.
func resolveWorkflowTarget(effShell string, shellSpecified bool, runsOn ast.Node) (sh string, target bool) {
	if shellSpecified {
		return normalizeShell(effShell)
	}
	if isWindowsOnly(runsOn) {
		return "", false
	}
	return "bash", true
}
