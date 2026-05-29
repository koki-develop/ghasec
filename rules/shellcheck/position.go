package shellcheck

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/rules"
)

// lineColToByteOffset converts a 1-based (line, col) position — counting runes
// per line (tabs = 1 column, matching shellcheck json1) — to a 0-based byte
// offset within s. If col exceeds the line length, it clamps to the line's
// newline; if the position is past the end, it returns len(s).
func lineColToByteOffset(s string, line, col int) int {
	curLine, curCol := 1, 1
	for i, r := range s {
		switch {
		case curLine == line && curCol == col:
			return i
		case curLine == line && r == '\n':
			// Requested column is beyond this line's content; clamp to newline.
			return i
		case curLine > line:
			return i
		}
		if r == '\n' {
			curLine++
			curCol = 1
		} else {
			curCol++
		}
	}
	return len(s)
}

// spanToken builds a synthetic YAML token for a shellcheck finding. The
// finding's 1-based (line, col)/(endLine, endCol) are positions within the
// masked script; masked has the same byte layout as the original run value, so
// byte offsets derived from masked are valid in value. It delegates to
// rules.ExpressionSpanToken, which maps the byte span to the correct YAML
// source position for block scalars and inline/quoted scalars alike.
func spanToken(node ast.Node, value, masked string, line, col, endLine, endCol int) *token.Token {
	start := lineColToByteOffset(masked, line, col)
	end := lineColToByteOffset(masked, endLine, endCol)
	if end <= start {
		end = start + 1
	}
	if end > len(value) {
		end = len(value)
	}
	if start > len(value) {
		start = len(value)
	}
	if start >= end {
		// Degenerate span (e.g. position past end): nudge to a 1-byte span.
		if start > 0 {
			start--
		}
		end = start + 1
		if end > len(value) {
			end = len(value)
		}
	}
	return rules.ExpressionSpanToken(node, value, start, end)
}
