package unpinnedtransitiveaction

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/lockfile"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unpinned-transitive-action"

var sha256DigestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// ActionFileFetcher fetches a remote action's parsed action.yml/action.yaml file.
// subPath is the subdirectory within the repo (e.g., "ec2/deploy" for
// "actions/aws/ec2/deploy@ref"). It is empty for root-level actions. The rule
// reports its errors to the user as they are, so each error must describe the
// request that failed, including the action.
type ActionFileFetcher interface {
	FetchActionFile(ctx context.Context, owner, repo, subPath, ref string) (*ast.File, error)
}

// Rule checks whether SHA-pinned or locked remote actions transitively use
// unpinned dependencies.
type Rule struct {
	Fetcher ActionFileFetcher
}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return true }

func (r *Rule) Why() string {
	return "Even when your workflow pins an action to a commit SHA, that action may internally reference other actions using mutable tags or branches. A compromised transitive dependency undermines the security of your entire pinning strategy"
}

func (r *Rule) Fix() string {
	return "Replace the action with an alternative that pins all of its own transitive dependencies to full commit SHAs, or open an issue/PR on the action's repository requesting SHA pinning"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectStepErrors(mapping.EachStep, func(step workflow.StepMapping) []*diagnostic.Error {
		return r.checkStep(step, mapping.Lock)
	})
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepErrors(mapping.EachStep, func(step workflow.StepMapping) []*diagnostic.Error {
		return r.checkStep(step, lockfile.Workflow{})
	})
}

// target is an action file to inspect: the action as a uses value names it,
// and the commit GitHub runs it at.
type target struct {
	owner, repo, subPath string
	// ref is the ref the uses value names, which is how the action is shown.
	ref string
	// commit is the commit the action is fetched at: ref itself when ref is a
	// full SHA, or the commit a lockfile records for it.
	commit string
	// dep is the lockfile's entry for the action, in a locked workflow.
	dep lockfile.Dependency
}

func (t target) String() string { return actionKey(t.owner, t.repo, t.subPath, t.ref) }

// checkStep inspects the action a step uses. In a workflow a lockfile locks,
// GitHub runs each action at the commit the lockfile records for it, so the
// action is inspected at that commit whatever its ref; otherwise only an action
// pinned to a full SHA has a fixed commit to inspect.
func (r *Rule) checkStep(step workflow.StepMapping, lock lockfile.Workflow) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}
	if !ref.IsRemote() {
		return nil
	}
	owner, repo := ref.OwnerRepo()
	if owner == "" {
		return nil
	}

	t := target{owner: owner, repo: repo, subPath: ref.SubPath(), ref: string(ref.Ref())}
	if lock.Locked() {
		dep, ok := lock.Lookup(ref.String())
		if !ok {
			return nil
		}
		t.commit, t.dep = dep.Commit, dep
	} else {
		if !ref.Ref().IsFullSHA() {
			return nil
		}
		t.commit = t.ref
	}

	visited := map[string]bool{}
	return r.checkTransitive(ref, t, lock, visited, nil)
}

// checkTransitive recursively inspects a remote action's transitive dependencies.
// path is nil for the root call (from checkStep) and non-nil for recursive calls.
// The distinction ensures the root action is excluded from the "via" chain.
func (r *Rule) checkTransitive(
	rootRef workflow.ActionRef,
	t target,
	lock lockfile.Workflow,
	visited map[string]bool,
	path []string,
) []*diagnostic.Error {
	key := actionKey(t.owner, t.repo, t.subPath, t.commit)
	if visited[key] {
		return nil
	}
	visited[key] = true

	// Build the "via" chain: for non-root calls, include self.
	// Root calls (path==nil) produce an empty via so the root action
	// does not appear in "(via ...)".
	var via []string
	if path != nil {
		via = make([]string, len(path)+1)
		copy(via, path)
		via[len(path)] = t.String()
	}

	f, err := r.Fetcher.FetchActionFile(context.Background(), t.owner, t.repo, t.subPath, t.commit)
	if err != nil {
		message := err.Error()
		if lock.Locked() {
			// The fetcher names the locked commit it requested, which the
			// workflow does not show, so name the action as it is written too.
			message = fmt.Sprintf("%q is locked: %s", t.String(), message)
		}
		return []*diagnostic.Error{{
			Token:   rootRef.Token(),
			Message: message,
		}}
	}

	if len(f.Docs) == 0 {
		return nil
	}
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return nil
	}
	actionMapping := workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}

	// For recursive calls, pass via as the child path.
	// For root calls (via==nil), pass an empty slice to mark children as non-root.
	childPath := via
	if childPath == nil {
		childPath = []string{}
	}

	var errs []*diagnostic.Error
	actionMapping.EachStep(func(step workflow.StepMapping) {
		innerRef, ok := step.Uses()
		if !ok {
			return
		}
		if innerRef.IsLocal() {
			return
		}

		// A self-repository reference resolves to this action's own repository
		// at the commit being inspected, so it is pinned by construction; its
		// own dependencies still need to be checked. A "$/...@ref" is rejected
		// by GitHub Actions and is not a pinning concern.
		if innerRef.IsSelfRepository() {
			if strings.Contains(innerRef.String(), "@") {
				return
			}
			self := t
			self.subPath = innerRef.SelfRepositoryPath()
			errs = append(errs, r.checkTransitive(rootRef, self, lock, visited, childPath)...)
			return
		}

		if innerRef.IsDocker() {
			if !sha256DigestRe.MatchString(innerRef.String()) {
				errs = append(errs, &diagnostic.Error{
					Token:   rootRef.Token(),
					Message: buildMessage(rootRef, innerRef.String(), via, true),
				})
			}
			return
		}

		innerOwner, innerRepo := innerRef.OwnerRepo()
		inner := target{owner: innerOwner, repo: innerRepo, subPath: innerRef.SubPath(), ref: string(innerRef.Ref())}
		if lock.Locked() {
			// GitHub runs an action inside a locked one at the commit the
			// lockfile records for it, from the parent's entry or the
			// workflow's list. One neither records fails the job when it
			// runs, so there is nothing to follow.
			dep, ok := lock.LookupFrom(t.dep, innerRef.String())
			if !ok {
				return
			}
			inner.commit, inner.dep = dep.Commit, dep
		} else {
			if !innerRef.Ref().IsFullSHA() {
				errs = append(errs, &diagnostic.Error{
					Token:   rootRef.Token(),
					Message: buildMessage(rootRef, innerRef.String(), via, false),
				})
				return
			}
			inner.commit = inner.ref
		}

		if innerOwner == "" {
			return
		}
		errs = append(errs, r.checkTransitive(rootRef, inner, lock, visited, childPath)...)
	})

	return errs
}

// actionKey formats an action as it appears in a "uses" value
// (owner/repo[/subPath]@ref). It identifies an action file, so actions in
// different subdirectories of the same repository and commit are distinct.
func actionKey(owner, repo, subPath, ref string) string {
	if subPath == "" {
		return fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	}
	return fmt.Sprintf("%s/%s/%s@%s", owner, repo, subPath, ref)
}

func buildMessage(rootRef workflow.ActionRef, unpinnedRef string, path []string, isDocker bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%q uses unpinned ", rootRef.String())
	if isDocker {
		sb.WriteString("Docker action ")
	} else {
		sb.WriteString("action ")
	}
	fmt.Fprintf(&sb, "%q", unpinnedRef)

	if len(path) > 0 {
		sb.WriteString(" via ")
		for i, p := range path {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%q", p)
		}
	}
	return sb.String()
}
