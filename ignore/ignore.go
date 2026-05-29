package ignore

import (
	"strings"

	"github.com/goccy/go-yaml/token"
)

const prefix = "ghasec-ignore"

// Directive represents a parsed ghasec-ignore comment.
type Directive struct {
	Token   *token.Token // The comment token itself
	Line    int          // Target line number (the line being suppressed)
	EndLine int          // Last line covered (== Line unless targeting a block scalar)
	RuleIDs []string     // Empty means all rules
	// UsedIDs tracks which specific rule IDs have been used (suppressed a diagnostic
	// or flagged as required-rule). For all-rules directives (empty RuleIDs),
	// any entry means the directive was used.
	UsedIDs map[string]bool
}

// MarkUsed marks a specific rule ID (or the directive itself for all-rules) as used.
func (d *Directive) MarkUsed(ruleID string) {
	if d.UsedIDs == nil {
		d.UsedIDs = make(map[string]bool)
	}
	d.UsedIDs[ruleID] = true
}

// IsUsed reports whether the directive (or a specific rule ID) has been used.
func (d *Directive) IsUsed(ruleID string) bool {
	return d.UsedIDs[ruleID]
}

// IsFullyUsed reports whether the entire directive has been used.
// For all-rules directives, any usage counts. For specific-rule directives,
// all rule IDs must be used.
func (d *Directive) IsFullyUsed() bool {
	if len(d.RuleIDs) == 0 {
		return len(d.UsedIDs) > 0
	}
	for _, id := range d.RuleIDs {
		if !d.UsedIDs[id] {
			return false
		}
	}
	return true
}

// Parse parses a comment token value into rule IDs.
// It trims leading/trailing whitespace, then checks if the result starts with
// "ghasec-ignore". Returns (nil, false) if the comment is not a directive.
// Returns (nil, true) for all-rules ignore, ([]string, true) for specific rules.
func Parse(comment string) (ruleIDs []string, ok bool) {
	s := strings.TrimSpace(comment)
	if !strings.HasPrefix(s, prefix) {
		return nil, false
	}
	rest := s[len(prefix):]
	if rest == "" {
		return nil, true
	}
	if rest[0] != ':' {
		return nil, false
	}
	parts := strings.SplitSeq(rest[1:], ",")
	for p := range parts {
		id := strings.TrimSpace(p)
		if id != "" {
			ruleIDs = append(ruleIDs, id)
		}
	}
	if len(ruleIDs) == 0 {
		return nil, true
	}
	return ruleIDs, true
}

// Collect walks the token chain from tk forward and returns all ignore directives.
// tk should be the first token in the chain (walk backward from any token to find it).
func Collect(tk *token.Token) []*Directive {
	head := tk
	var directives []*Directive
	for ; tk != nil; tk = tk.Next {
		if tk.Type != token.CommentType {
			continue
		}
		ruleIDs, ok := Parse(tk.Value)
		if !ok {
			continue
		}
		line := targetLine(tk)
		directives = append(directives, &Directive{
			Token:   tk,
			Line:    line,
			EndLine: blockEndLine(head, line),
			RuleIDs: ruleIDs,
		})
	}
	return directives
}

// blockEndLine returns the last line covered by a block scalar (literal `|` or
// folded `>`) whose introducer token sits on line. If no block scalar starts on
// line, it returns line unchanged. This lets a directive targeting a multi-line
// `run:` (or any block scalar) cover diagnostics reported on the block's inner
// lines, not just the introducer line.
func blockEndLine(head *token.Token, line int) int {
	for tk := head; tk != nil; tk = tk.Next {
		if tk.Type != token.LiteralType && tk.Type != token.FoldedType {
			continue
		}
		if tk.Position == nil || tk.Position.Line != line {
			continue
		}
		// The block content is the next non-comment token (an inline comment may
		// sit between the introducer and the content).
		content := tk.Next
		for content != nil && content.Type == token.CommentType {
			content = content.Next
		}
		if content == nil || content.Position == nil {
			return line
		}
		// The token following the content marks the block boundary: the block
		// ends on the line just before it. This is accurate for both literal and
		// folded scalars, whose content token position is inconsistent (it points
		// at the first line for some literals, the last for folded).
		if content.Next != nil && content.Next.Position != nil {
			if end := content.Next.Position.Line - 1; end > line {
				return end
			}
			return line
		}
		// Block is the last token in the file: there is no following token to
		// bound it. In this case the content token's position reliably points at
		// the block's last line.
		if end := content.Position.Line; end > line {
			return end
		}
		return line
	}
	return line
}

// KeywordToken returns a synthetic token pointing to the "ghasec-ignore" keyword
// within the comment. Used for diagnostic positioning on all-rules directives.
func (d *Directive) KeywordToken() *token.Token {
	idx := strings.Index(d.Token.Value, prefix)
	if idx < 0 {
		return d.Token
	}
	return d.syntheticToken(idx, len(prefix))
}

// RuleIDToken returns a synthetic token pointing to a specific rule ID within
// the comment. Used for diagnostic positioning on per-rule errors.
func (d *Directive) RuleIDToken(ruleID string) *token.Token {
	// Search after the colon to avoid matching the prefix itself
	colonIdx := strings.Index(d.Token.Value, prefix+":")
	if colonIdx >= 0 {
		searchStart := colonIdx + len(prefix) + 1
		idx := strings.Index(d.Token.Value[searchStart:], ruleID)
		if idx >= 0 {
			return d.syntheticToken(searchStart+idx, len(ruleID))
		}
	}
	return d.Token
}

// syntheticToken creates a token pointing to a substring within the comment value.
// valueIndex is the index into Token.Value, length is the substring length.
//
// Token.Value holds the comment text after '#'. Normally go-yaml points the
// comment token's column at the leading '#', so Value[0] sits one column to the
// right (hence "+1 for '#'"). A comment that immediately follows a block scalar
// header (`|`/`>`) is reported differently: its column already points at Value[0],
// so the usual +1 would overshoot by one column. Compensate so the caret lands on
// the substring in both cases.
func (d *Directive) syntheticToken(valueIndex, length int) *token.Token {
	cp := *d.Token
	cp.Value = d.Token.Value[valueIndex : valueIndex+length]
	if d.Token.Position == nil {
		return &cp
	}
	skip := valueIndex + 1 // +1 for '#'
	if followsBlockScalarHeader(d.Token) {
		skip = valueIndex
	}
	cp.Position = &token.Position{
		Line:   d.Token.Position.Line,
		Column: d.Token.Position.Column + skip,
		Offset: d.Token.Position.Offset + skip,
	}
	return &cp
}

// followsBlockScalarHeader reports whether the comment sits immediately after a
// block scalar header (`|` or `>`) on the same line. go-yaml reports such a
// comment's column one position further right (at the first character of its
// value rather than at the '#'), so syntheticToken must not add the extra '#'
// offset for it.
func followsBlockScalarHeader(tk *token.Token) bool {
	prev := tk.Prev
	return prev != nil &&
		(prev.Type == token.LiteralType || prev.Type == token.FoldedType) &&
		prev.Position != nil && tk.Position != nil &&
		prev.Position.Line == tk.Position.Line
}

// targetLine determines which line this ignore directive applies to.
// Inline comments (Prev is a non-comment token on the same line) target their own line.
// Previous-line comments target the next line.
func targetLine(commentTk *token.Token) int {
	if commentTk.Position == nil {
		return 0
	}
	if commentTk.Prev != nil &&
		commentTk.Prev.Type != token.CommentType &&
		commentTk.Prev.Position != nil &&
		commentTk.Prev.Position.Line == commentTk.Position.Line {
		return commentTk.Position.Line
	}
	return commentTk.Position.Line + 1
}
