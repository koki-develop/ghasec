package unpinnedtransitiveaction

import (
	"fmt"
	"regexp"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/lockfile"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unpinned-transitive-action"

var sha256DigestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// Rule checks whether SHA-pinned or locked remote actions transitively use
// unpinned dependencies.
type Rule struct {
	Fetcher rules.ActionFileFetcher
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

// checkStep inspects the action a step uses and the actions it reaches, at
// the commits GitHub runs them at.
func (r *Rule) checkStep(step workflow.StepMapping, lock lockfile.Workflow) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}
	root, ok := rules.StepRemoteAction(ref, lock)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	rules.WalkTransitive(r.Fetcher, root, lock, rules.TransitiveVisitor{
		Uses: func(_ rules.RemoteAction, inner workflow.ActionRef, via []string) {
			switch {
			case inner.IsDocker():
				if sha256DigestRe.MatchString(inner.String()) {
					return
				}
				errs = append(errs, &diagnostic.Error{
					Token:   ref.Token(),
					Message: rules.TransitiveMessage(ref, "unpinned Docker action", inner.String(), via),
				})
			case !lock.Locked() && !inner.Ref().IsFullSHA():
				// In a locked workflow, GitHub runs the action at the commit
				// the lockfile records, whatever its ref.
				errs = append(errs, &diagnostic.Error{
					Token:   ref.Token(),
					Message: rules.TransitiveMessage(ref, "unpinned action", inner.String(), via),
				})
			}
		},
		FetchError: func(a rules.RemoteAction, err error) {
			message := err.Error()
			if lock.Locked() {
				// The fetcher names the locked commit it requested, which the
				// workflow does not show, so name the action as it is written too.
				message = fmt.Sprintf("%q is locked: %s", a.String(), message)
			}
			errs = append(errs, &diagnostic.Error{Token: ref.Token(), Message: message})
		},
	})
	return errs
}
