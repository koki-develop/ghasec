package mismatchedshatag

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/git"
	"github.com/koki-develop/ghasec/rules"
)

const id = "mismatched-sha-tag"

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
func (r *Rule) Online() bool   { return true }

func (r *Rule) Check(mapping *ast.MappingNode) []*diagnostic.Error {
	if r.Resolver == nil {
		return nil
	}

	var errs []*diagnostic.Error
	rules.EachStep(mapping, func(step *ast.MappingNode) {
		errs = append(errs, r.checkStep(step)...)
	})
	return errs
}

func (r *Rule) checkStep(step *ast.MappingNode) []*diagnostic.Error {
	usesValue, usesToken, ok := rules.StepUsesValue(step)
	if !ok {
		return nil
	}

	if rules.IsLocalAction(usesValue) || rules.IsDockerAction(usesValue) {
		return nil
	}

	atIdx := strings.LastIndex(usesValue, "@")
	if atIdx == -1 {
		return nil
	}

	sha := usesValue[atIdx+1:]
	if !git.Ref(sha).IsFullSHA() {
		return nil
	}

	// Extract the comment from the next token.
	tk := usesToken
	if tk.Next == nil || tk.Next.Type.String() != "Comment" {
		return nil
	}

	tag := strings.TrimSpace(tk.Next.Value)
	if tag == "" {
		return nil
	}

	if !git.Ref(tag).IsValid() {
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
