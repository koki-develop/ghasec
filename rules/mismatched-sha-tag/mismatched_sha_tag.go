package mismatchedshatag

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

const id = "mismatched-sha-tag"

var fullSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TagResolver resolves a git tag to its commit SHA via the GitHub API.
// The returned SHA must be a full 40-character lowercase hexadecimal commit hash.
type TagResolver interface {
	ResolveTagSHA(ctx context.Context, owner, repo, tag string) (string, error)
}

type Rule struct {
	Resolver TagResolver
}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }

func (r *Rule) Check(f *ast.File) []*diagnostic.Error {
	if r.Resolver == nil {
		return nil
	}

	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		return nil
	}

	mapping := rules.TopLevelMapping(f.Docs[0])
	if mapping == nil {
		return nil
	}

	jobsKV := rules.FindKey(mapping, "jobs")
	if jobsKV == nil {
		return nil
	}

	jobsMapping, ok := jobsKV.Value.(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	for _, jobEntry := range jobsMapping.Values {
		jobMapping, ok := jobEntry.Value.(*ast.MappingNode)
		if !ok {
			continue
		}

		stepsKV := rules.FindKey(jobMapping, "steps")
		if stepsKV == nil {
			continue
		}

		seq, ok := stepsKV.Value.(*ast.SequenceNode)
		if !ok {
			continue
		}

		for _, step := range seq.Values {
			stepMapping, ok := step.(*ast.MappingNode)
			if !ok {
				continue
			}
			errs = append(errs, r.checkStep(stepMapping)...)
		}
	}
	return errs
}

func (r *Rule) checkStep(step *ast.MappingNode) []*diagnostic.Error {
	usesKV := rules.FindKey(step, "uses")
	if usesKV == nil {
		return nil
	}

	var usesValue string
	switch v := usesKV.Value.(type) {
	case *ast.StringNode:
		usesValue = v.Value
	case *ast.LiteralNode:
		usesValue = v.Value.Value
	default:
		return nil
	}

	if strings.HasPrefix(usesValue, "./") || strings.HasPrefix(usesValue, "docker://") {
		return nil
	}

	atIdx := strings.LastIndex(usesValue, "@")
	if atIdx == -1 {
		return nil
	}

	sha := usesValue[atIdx+1:]
	if !fullSHAPattern.MatchString(sha) {
		return nil
	}

	// Extract the comment from the next token.
	tk := usesKV.Value.GetToken()
	if tk.Next == nil || tk.Next.Type.String() != "Comment" {
		return nil
	}

	tag := strings.TrimSpace(tk.Next.Value)
	if tag == "" {
		return nil
	}

	if !isValidGitRef(tag) {
		return nil
	}

	// Parse owner/repo from the action reference.
	actionPath := usesValue[:atIdx]
	parts := strings.SplitN(actionPath, "/", 3)
	if len(parts) < 2 {
		return nil
	}
	owner := parts[0]
	repo := parts[1]

	// Build a token pointing at just the tag text.
	// The comment token's Offset points to '#', and Value contains the text after '#'.
	// So the tag starts at Offset + 1 (skip '#') + leading whitespace.
	rawComment := tk.Next
	leading := len(rawComment.Value) - len(tag)
	skip := 1 + leading // 1 for '#', then leading whitespace
	tagTk := &token.Token{
		Type:  rawComment.Type,
		Value: tag,
		Position: &token.Position{
			Line:   rawComment.Position.Line,
			Column: rawComment.Position.Column + skip,
			Offset: rawComment.Position.Offset + skip,
		},
	}

	resolvedSHA, err := r.Resolver.ResolveTagSHA(context.Background(), owner, repo, tag)
	if err != nil {
		return []*diagnostic.Error{{
			Token:       tagTk,
			BeforeToken: tk,
			Message:     fmt.Sprintf("failed to resolve tag %q for action %q: %v", tag, usesValue, err),
		}}
	}

	if resolvedSHA != sha {
		return []*diagnostic.Error{{
			Token:       tagTk,
			BeforeToken: tk,
			Message:     fmt.Sprintf("action %q references tag %q, but the tag points to commit %q", usesValue, tag, resolvedSHA),
		}}
	}

	return nil
}

// isValidGitRef checks whether a string is a valid git reference name
// according to the rules in git-check-ref-format(1).
func isValidGitRef(ref string) bool {
	if ref == "" || ref == "@" {
		return false
	}

	// Cannot begin or end with a slash, or contain consecutive slashes.
	if strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return false
	}
	if strings.Contains(ref, "//") {
		return false
	}

	// Cannot begin with a dash.
	if strings.HasPrefix(ref, "-") {
		return false
	}

	// Cannot end with a dot.
	if strings.HasSuffix(ref, ".") {
		return false
	}

	// Cannot end with ".lock".
	if strings.HasSuffix(ref, ".lock") {
		return false
	}

	// Cannot contain "..".
	if strings.Contains(ref, "..") {
		return false
	}

	// Cannot contain "@{".
	if strings.Contains(ref, "@{") {
		return false
	}

	// Cannot contain a backslash.
	if strings.Contains(ref, "\\") {
		return false
	}

	// Check each byte for forbidden characters.
	for i := 0; i < len(ref); i++ {
		b := ref[i]
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
	for _, component := range strings.Split(ref, "/") {
		if strings.HasPrefix(component, ".") {
			return false
		}
	}

	return true
}
