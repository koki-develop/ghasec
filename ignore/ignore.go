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
	parts := strings.Split(rest[1:], ",")
	for _, p := range parts {
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
			RuleIDs: ruleIDs,
		})
	}
	return directives
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
// The position is shifted by +1 for the '#' character that precedes the Value.
func (d *Directive) syntheticToken(valueIndex, length int) *token.Token {
	cp := *d.Token
	cp.Value = d.Token.Value[valueIndex : valueIndex+length]
	if d.Token.Position == nil {
		return &cp
	}
	skip := valueIndex + 1 // +1 for '#'
	cp.Position = &token.Position{
		Line:   d.Token.Position.Line,
		Column: d.Token.Position.Column + skip,
		Offset: d.Token.Position.Offset + skip,
	}
	return &cp
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
