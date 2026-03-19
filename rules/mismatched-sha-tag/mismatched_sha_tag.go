package mismatchedshatag

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/git"
	"github.com/koki-develop/ghasec/workflow"
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

func (r *Rule) Check(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	if r.Resolver == nil {
		return nil
	}

	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		errs = append(errs, r.checkStep(step)...)
	})
	return errs
}

func (r *Rule) checkStep(step workflow.StepMapping) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if ref.IsLocal() || ref.IsDocker() {
		return nil
	}

	if !ref.Ref().IsFullSHA() {
		return nil
	}

	// Extract the comment from the next token.
	tk := ref.Token()
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
	owner, repo := ref.OwnerRepo()
	if owner == "" {
		return nil
	}

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
			Token:         tagTk,
			ContextTokens: []*token.Token{step.JobsKeyToken(), step.JobKeyToken(), tk},
			Message:       fmt.Sprintf("failed to resolve tag %q for action %q: %v", tag, ref.String(), err),
		}}
	}

	if resolvedSHA != string(ref.Ref()) {
		return []*diagnostic.Error{{
			Token:         tagTk,
			ContextTokens: []*token.Token{step.JobsKeyToken(), step.JobKeyToken(), tk},
			Message:       fmt.Sprintf("action %q references tag %q, but the tag points to commit %q", ref.String(), tag, resolvedSHA),
		}}
	}

	return nil
}
