package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/lockfile"
	"github.com/koki-develop/ghasec/workflow"
)

// ActionFileFetcher fetches a remote action's parsed action.yml/action.yaml file.
// subPath is the subdirectory within the repo (e.g., "ec2/deploy" for
// "actions/aws/ec2/deploy@ref"). It is empty for root-level actions. Rules
// report its errors to the user as they are, so each error must describe the
// request that failed, including the action.
type ActionFileFetcher interface {
	FetchActionFile(ctx context.Context, owner, repo, subPath, ref string) (*ast.File, error)
}

// RemoteAction is an action file in another repository: the action as a uses
// value names it, and the commit GitHub runs it at.
type RemoteAction struct {
	Owner, Repo, SubPath string
	// Ref is the ref the uses value names, which is how the action is shown.
	Ref string
	// Commit is the commit the action is fetched at: Ref itself when Ref is a
	// full SHA, or the commit a lockfile records for it.
	Commit string
	// Dep is the lockfile's entry for the action, in a locked workflow.
	Dep lockfile.Dependency
}

// String formats the action as a uses value names it
// (owner/repo[/subPath]@ref).
func (a RemoteAction) String() string { return remoteActionKey(a.Owner, a.Repo, a.SubPath, a.Ref) }

// StepRemoteAction returns the remote action a step's uses value names, with
// the commit GitHub runs it at. In a workflow a lockfile locks, GitHub runs
// each action at the commit the lockfile records for it, whatever its ref;
// otherwise only an action pinned to a full SHA has a fixed commit. It reports
// false for any other uses value.
func StepRemoteAction(ref workflow.ActionRef, lock lockfile.Workflow) (RemoteAction, bool) {
	if !ref.IsRemote() {
		return RemoteAction{}, false
	}
	owner, repo := ref.OwnerRepo()
	if owner == "" {
		return RemoteAction{}, false
	}
	a := RemoteAction{Owner: owner, Repo: repo, SubPath: ref.SubPath(), Ref: string(ref.Ref())}
	if lock.Locked() {
		dep, ok := lock.Lookup(ref.String())
		if !ok {
			return RemoteAction{}, false
		}
		a.Commit, a.Dep = dep.Commit, dep
		return a, true
	}
	if !ref.Ref().IsFullSHA() {
		return RemoteAction{}, false
	}
	a.Commit = a.Ref
	return a, true
}

// TransitiveVisitor receives what WalkTransitive finds.
type TransitiveVisitor struct {
	// Uses is called for each remote or Docker uses value in the file of an
	// action reached. parent is that action, and via names the actions
	// between the step's action and parent, parent included; via is empty
	// when parent is the step's action.
	Uses func(parent RemoteAction, ref workflow.ActionRef, via []string)
	// FetchError is called for an action whose file could not be fetched.
	FetchError func(a RemoteAction, err error)
}

// WalkTransitive fetches the file of the action root and of each action it
// uses in turn, following each at the commit GitHub runs it at. A
// self-repository reference ("$/...") inside an action resolves to that
// action's own repository at the same commit and is followed with the
// parent's lockfile entry. A remote action is followed at the commit the
// lockfile records for it from the parent's entry or the workflow's list, in
// a locked workflow, and at its ref when that is a full SHA, otherwise. Each
// action file is fetched once.
func WalkTransitive(fetcher ActionFileFetcher, root RemoteAction, lock lockfile.Workflow, visit TransitiveVisitor) {
	w := &transitiveWalk{fetcher: fetcher, lock: lock, visit: visit, visited: map[string]bool{}}
	w.walk(root, nil)
}

type transitiveWalk struct {
	fetcher ActionFileFetcher
	lock    lockfile.Workflow
	visit   TransitiveVisitor
	visited map[string]bool
}

// walk inspects the file of a. path is nil for the step's action and non-nil
// for the actions it reaches, so the step's action is left out of via.
func (w *transitiveWalk) walk(a RemoteAction, path []string) {
	key := remoteActionKey(a.Owner, a.Repo, a.SubPath, a.Commit)
	if w.visited[key] {
		return
	}
	w.visited[key] = true

	var via []string
	if path != nil {
		via = make([]string, len(path)+1)
		copy(via, path)
		via[len(path)] = a.String()
	}

	f, err := w.fetcher.FetchActionFile(context.Background(), a.Owner, a.Repo, a.SubPath, a.Commit)
	if err != nil {
		if w.visit.FetchError != nil {
			w.visit.FetchError(a, err)
		}
		return
	}
	if len(f.Docs) == 0 {
		return
	}
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return
	}

	childPath := via
	if childPath == nil {
		childPath = []string{}
	}

	workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}.EachStep(func(step workflow.StepMapping) {
		ref, ok := step.Uses()
		if !ok || ref.IsLocal() {
			return
		}

		// A "$/...@ref" is rejected by GitHub Actions, so there is nothing to
		// follow.
		if ref.IsSelfRepository() {
			if strings.Contains(ref.String(), "@") {
				return
			}
			self := a
			self.SubPath = ref.SelfRepositoryPath()
			w.walk(self, childPath)
			return
		}

		if w.visit.Uses != nil {
			w.visit.Uses(a, ref, via)
		}
		if ref.IsDocker() {
			return
		}

		owner, repo := ref.OwnerRepo()
		inner := RemoteAction{Owner: owner, Repo: repo, SubPath: ref.SubPath(), Ref: string(ref.Ref())}
		if w.lock.Locked() {
			// GitHub runs an action inside a locked one at the commit the
			// lockfile records for it, from the parent's entry or the
			// workflow's list. One neither records fails the job when it
			// runs, so there is nothing to follow.
			dep, ok := w.lock.LookupFrom(a.Dep, ref.String())
			if !ok {
				return
			}
			inner.Commit, inner.Dep = dep.Commit, dep
		} else {
			if !ref.Ref().IsFullSHA() {
				return
			}
			inner.Commit = inner.Ref
		}
		if owner == "" {
			return
		}
		w.walk(inner, childPath)
	})
}

// remoteActionKey formats an action as it appears in a "uses" value
// (owner/repo[/subPath]@ref). It identifies an action file, so actions in
// different subdirectories of the same repository and commit are distinct.
func remoteActionKey(owner, repo, subPath, ref string) string {
	if subPath == "" {
		return fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	}
	return fmt.Sprintf("%s/%s/%s@%s", owner, repo, subPath, ref)
}

// TransitiveMessage formats a report about the uses value inner found inside
// the action a step's uses value root names, reached through via:
// `"<root>" uses <kind> "<inner>" via "<via>", ...`.
func TransitiveMessage(root workflow.ActionRef, kind, inner string, via []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%q uses %s %q", root.String(), kind, inner)
	if len(via) > 0 {
		sb.WriteString(" via ")
		for i, p := range via {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%q", p)
		}
	}
	return sb.String()
}
