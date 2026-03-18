package git

import (
	"regexp"
	"strings"
)

// Ref represents a git reference string (tag, branch name, or commit SHA).
type Ref string

var fullSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// IsFullSHA reports whether the ref is a full 40-character lowercase
// hexadecimal commit SHA.
func (r Ref) IsFullSHA() bool {
	return fullSHAPattern.MatchString(string(r))
}

// IsValid reports whether the ref is a valid git reference name according to
// the rules in git-check-ref-format(1).
func (r Ref) IsValid() bool {
	s := string(r)

	if s == "" || s == "@" {
		return false
	}

	// Cannot begin or end with a slash, or contain consecutive slashes.
	if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	if strings.Contains(s, "//") {
		return false
	}

	// Cannot begin with a dash.
	if strings.HasPrefix(s, "-") {
		return false
	}

	// Cannot end with a dot.
	if strings.HasSuffix(s, ".") {
		return false
	}

	// Cannot end with ".lock".
	if strings.HasSuffix(s, ".lock") {
		return false
	}

	// Cannot contain "..".
	if strings.Contains(s, "..") {
		return false
	}

	// Cannot contain "@{".
	if strings.Contains(s, "@{") {
		return false
	}

	// Cannot contain a backslash.
	if strings.Contains(s, "\\") {
		return false
	}

	// Check each byte for forbidden characters.
	for i := 0; i < len(s); i++ {
		b := s[i]
		// ASCII control characters (< 0x20) or DEL (0x7f).
		if b < 0x20 || b == 0x7f {
			return false
		}
		// Space, tilde, caret, colon, question mark, asterisk, open bracket.
		switch b {
		case ' ', '~', '^', ':', '?', '*', '[':
			return false
		}
	}

	// No slash-separated component can begin with a dot.
	for component := range strings.SplitSeq(s, "/") {
		if strings.HasPrefix(component, ".") {
			return false
		}
	}

	return true
}
