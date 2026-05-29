package shellcheck

import (
	"strings"

	"github.com/koki-develop/ghasec/expression"
)

// maskRegion identifies the span of a masked ${{ }} expression in the masked
// script, in 1-based rune columns (matching shellcheck json1 column semantics).
// colEnd is exclusive, aligning with shellcheck's exclusive endColumn.
type maskRegion struct {
	line     int
	colStart int
	colEnd   int
}

// maskExpressions replaces every ${{ ... }} expression in script with a
// byte-length-preserving, all-uppercase variable placeholder (e.g. ${GGGGG}),
// preserving newlines. Using a *variable* placeholder — rather than a constant
// literal — prevents shellcheck from constant-folding (which would yield false
// positives like SC2050/SC2154/SC2157). All-uppercase names are treated by
// shellcheck as possible environment variables, suppressing SC2154 on the
// placeholder itself.
//
// It returns the masked script, the rune-column regions occupied by the
// placeholders (used to drop findings that fall entirely within synthesized
// text), and whether the script contained a malformed expression that could not
// be extracted (e.g. an unterminated "${{"). When malformed, the caller skips
// shellcheck entirely: the broken expression would reach shellcheck unmasked and
// produce meaningless parse errors, and the malformed expression is already
// reported by the invalid-expression rule.
//
// Byte length is preserved so that the masked script's line/column positions
// map 1:1 back to the original YAML source.
func maskExpressions(script string) (string, []maskRegion, bool) {
	spans, errs := expression.ExtractExpressions(script)
	hadErrors := len(errs) > 0
	if len(spans) == 0 {
		return script, nil, hadErrors
	}

	var b strings.Builder
	b.Grow(len(script))
	var regions []maskRegion
	line, col := 1, 1

	writeVerbatim := func(seg string) {
		b.WriteString(seg)
		for _, r := range seg {
			if r == '\n' {
				line++
				col = 1
			} else {
				col++
			}
		}
	}

	writeMask := func(seg string) {
		masked := maskPlaceholder(seg)
		b.WriteString(masked)
		curStartCol := col
		for _, r := range masked {
			if r == '\n' {
				regions = append(regions, maskRegion{line: line, colStart: curStartCol, colEnd: col})
				line++
				col = 1
				curStartCol = col
			} else {
				col++
			}
		}
		regions = append(regions, maskRegion{line: line, colStart: curStartCol, colEnd: col})
	}

	prev := 0
	for _, sp := range spans {
		if sp.Start < prev || sp.End > len(script) || sp.Start >= sp.End {
			continue
		}
		writeVerbatim(script[prev:sp.Start])
		writeMask(script[sp.Start:sp.End])
		prev = sp.End
	}
	writeVerbatim(script[prev:])

	return b.String(), regions, hadErrors
}

// maskPlaceholder produces the byte-length-preserving replacement for a single
// ${{ ... }} segment. For a single-line segment it yields a variable expansion
// "${GGG...}" (kept dynamic so shellcheck won't constant-fold). For the rare
// (defensive) multi-line segment it falls back to a bare run of 'G' with
// newlines preserved.
func maskPlaceholder(seg string) string {
	if strings.ContainsAny(seg, "\r\n") {
		var sb strings.Builder
		sb.Grow(len(seg))
		for i := 0; i < len(seg); i++ {
			if c := seg[i]; c == '\n' || c == '\r' {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('G')
			}
		}
		return sb.String()
	}
	n := len(seg)
	if n < 4 {
		// ${{ }} is always >= 6 bytes; this guards only against unexpected input.
		return strings.Repeat("G", n)
	}
	return "${" + strings.Repeat("G", n-3) + "}"
}

// isInsideMask reports whether a shellcheck finding spanning [col, endCol) on
// the given 1-based line lies entirely within a masked region. Such findings
// are shellcheck commenting on synthesized placeholder text and are dropped.
func isInsideMask(regions []maskRegion, line, col, endCol int) bool {
	for _, r := range regions {
		if r.line == line && col >= r.colStart && endCol <= r.colEnd {
			return true
		}
	}
	return false
}
