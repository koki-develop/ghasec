package mismatchedshatag

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/git"
	"github.com/koki-develop/ghasec/github"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "mismatched-sha-tag"

// RefResolver resolves the git ref written in a SHA pin's comment via the GitHub API.
type RefResolver interface {
	// ResolveTagSHA resolves a git tag to its commit SHA. The returned SHA must
	// be a full 40-character lowercase hexadecimal commit hash. When the tag
	// does not exist, the error must satisfy github.IsNotFound.
	ResolveTagSHA(ctx context.Context, owner, repo, tag string) (string, error)
	// BranchExists reports whether a branch with the given name exists.
	BranchExists(ctx context.Context, owner, repo, branch string) (bool, error)
	// BranchContainsCommit reports whether the commit is the head of an
	// existing branch or one of its ancestors.
	BranchContainsCommit(ctx context.Context, owner, repo, branch, sha string) (bool, error)
	// RepoExists reports whether the repository exists and is visible to the
	// current credentials.
	RepoExists(ctx context.Context, owner, repo string) (bool, error)
}

type Rule struct {
	Resolver RefResolver
}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return true }

func (r *Rule) Why() string {
	return "If the SHA and the tag or branch in its comment drift apart, the comment becomes a false assertion. A reviewer may approve the workflow believing a vetted release is in use while a different commit runs"
}

func (r *Rule) Fix() string {
	return "Update the SHA to match the tag or branch in the comment, or correct the comment to match the SHA"
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
	if !ref.IsRemote() {
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

	ctx := context.Background()
	resolvedSHA, err := r.Resolver.ResolveTagSHA(ctx, owner, repo, tag)
	if github.IsNotFound(err) {
		return r.checkNonTag(ctx, ref, owner, repo, tag, tagTk)
	}
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

// checkNonTag handles a comment that does not name a tag. The comment may
// name a branch instead: a branch moves, so the pinned commit must be its
// head or one of its ancestors rather than equal to its current head.
func (r *Rule) checkNonTag(ctx context.Context, ref workflow.ActionRef, owner, repo, name string, tk *token.Token) []*diagnostic.Error {
	sha := string(ref.Ref())

	isBranch, err := r.Resolver.BranchExists(ctx, owner, repo, name)
	if err != nil {
		return []*diagnostic.Error{{
			Token:   tk,
			Message: fmt.Sprintf("failed to resolve branch %q for %q: %v", name, ref.String(), err),
		}}
	}

	if isBranch {
		onBranch, err := r.Resolver.BranchContainsCommit(ctx, owner, repo, name, sha)
		if err != nil {
			return []*diagnostic.Error{{
				Token:   tk,
				Message: fmt.Sprintf("failed to verify branch %q for %q: %v", name, ref.String(), err),
			}}
		}
		if !onBranch {
			return []*diagnostic.Error{{
				Token:   tk,
				Message: fmt.Sprintf("commit must belong to branch %q of %s/%s", name, owner, repo),
			}}
		}
		return nil
	}

	// GitHub answers HTTP 404 for a repository the credentials cannot see, so
	// make sure the repository is visible before saying that the comment
	// names nothing in it.
	exists, err := r.Resolver.RepoExists(ctx, owner, repo)
	if err != nil {
		return []*diagnostic.Error{{
			Token:   tk,
			Message: fmt.Sprintf("failed to resolve %q for %q: %v", name, ref.String(), err),
		}}
	}
	if !exists {
		return []*diagnostic.Error{{
			Token:   tk,
			Message: fmt.Sprintf("failed to resolve %q for %q: repository %s/%s was not found or is not accessible", name, ref.String(), owner, repo),
		}}
	}

	return []*diagnostic.Error{{
		Token:   tk,
		Message: fmt.Sprintf("comment %q must name an existing tag or branch of %s/%s", name, owner, repo),
	}}
}
