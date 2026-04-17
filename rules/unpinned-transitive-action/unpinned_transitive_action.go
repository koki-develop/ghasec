package unpinnedtransitiveaction

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unpinned-transitive-action"

var sha256DigestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// ActionFileFetcher fetches a remote action's parsed action.yml/action.yaml file.
// subPath is the subdirectory within the repo (e.g., "ec2/deploy" for
// "actions/aws/ec2/deploy@ref"). It is empty for root-level actions.
type ActionFileFetcher interface {
	FetchActionFile(ctx context.Context, owner, repo, subPath, ref string) (*ast.File, error)
}

// Rule checks whether SHA-pinned remote actions transitively use unpinned dependencies.
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
	return rules.CollectStepErrors(mapping.EachStep, r.checkStep)
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepErrors(mapping.EachStep, r.checkStep)
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

	owner, repo := ref.OwnerRepo()
	if owner == "" {
		return nil
	}

	visited := map[string]bool{}
	return r.checkTransitive(ref, owner, repo, ref.SubPath(), string(ref.Ref()), visited, nil)
}

// checkTransitive recursively inspects a remote action's transitive dependencies.
// path is nil for the root call (from checkStep) and non-nil for recursive calls.
// The distinction ensures the root action is excluded from the "via" chain.
func (r *Rule) checkTransitive(
	rootRef workflow.ActionRef,
	owner, repo, subPath, ref string,
	visited map[string]bool,
	path []string,
) []*diagnostic.Error {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
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
		via[len(path)] = key
	}

	f, err := r.Fetcher.FetchActionFile(context.Background(), owner, repo, subPath, ref)
	if err != nil {
		return []*diagnostic.Error{{
			Token:   rootRef.Token(),
			Message: fmt.Sprintf("failed to fetch action.yml for %q: %v", key, err),
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

		if innerRef.IsDocker() {
			if !sha256DigestRe.MatchString(innerRef.String()) {
				errs = append(errs, &diagnostic.Error{
					Token:   rootRef.Token(),
					Message: buildMessage(rootRef, innerRef.String(), via, true),
				})
			}
			return
		}

		if !innerRef.Ref().IsFullSHA() {
			errs = append(errs, &diagnostic.Error{
				Token:   rootRef.Token(),
				Message: buildMessage(rootRef, innerRef.String(), via, false),
			})
			return
		}

		innerOwner, innerRepo := innerRef.OwnerRepo()
		if innerOwner == "" {
			return
		}
		errs = append(errs, r.checkTransitive(
			rootRef, innerOwner, innerRepo, innerRef.SubPath(), string(innerRef.Ref()), visited, childPath,
		)...)
	})

	return errs
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
