package mismatchedshatag

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/git"
	"github.com/koki-develop/ghasec/rules"
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

func (r *Rule) Why() string {
	return "If the SHA and tag comment drift apart, the comment becomes a false assertion. A reviewer may approve the workflow believing a vetted release is in use while a different commit runs"
}

func (r *Rule) Fix() string {
	return "Update the SHA to match the tag in the comment, or correct the comment to match the SHA"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return slices.Concat(
		rules.CollectJobErrors(mapping.EachJob, r.checkJob),
		rules.CollectStepErrors(mapping.EachStep, r.checkStep),
	)
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepErrors(mapping.EachStep, r.checkStep)
}

func (r *Rule) checkJob(_ *token.Token, job workflow.JobMapping) []*diagnostic.Error {
	ref, ok := job.Uses()
	if !ok {
		return nil
	}
	return r.check(ref)
}

func (r *Rule) checkStep(step workflow.StepMapping) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}
	return r.check(ref)
}

func (r *Rule) check(ref workflow.ActionRef) []*diagnostic.Error {
	if ref.IsLocal() || ref.IsDocker() {
		return nil
	}

	if !ref.Ref().IsFullSHA() {
		return nil
	}

	tk := ref.Token()
	if tk.Next == nil || tk.Next.Type != token.CommentType {
		return nil
	}

	tag := strings.TrimSpace(tk.Next.Value)
	if tag == "" {
		return nil
	}

	if !git.Ref(tag).IsValid() {
		return nil
	}

	owner, repo := ref.OwnerRepo()
	if owner == "" {
		return nil
	}

	rawComment := tk.Next
	leading := len(rawComment.Value) - len(tag)
	skip := 1 + leading
	tagTk := &token.Token{
		Type:  rawComment.Type,
		Value: tag,
		Prev:  rawComment,
		Position: &token.Position{
			Line:   rawComment.Position.Line,
			Column: rawComment.Position.Column + skip,
			Offset: rawComment.Position.Offset + skip,
		},
	}

	resolvedSHA, err := r.Resolver.ResolveTagSHA(context.Background(), owner, repo, tag)
	if err != nil {
		return []*diagnostic.Error{{
			Token:   tagTk,
			Message: fmt.Sprintf("failed to resolve tag %q for %q: %v", tag, ref.String(), err),
		}}
	}

	if resolvedSHA != string(ref.Ref()) {
		return []*diagnostic.Error{{
			Token:   tagTk,
			Message: fmt.Sprintf("%q points to commit %q, not the pinned commit", tag, resolvedSHA),
		}}
	}

	return nil
}
