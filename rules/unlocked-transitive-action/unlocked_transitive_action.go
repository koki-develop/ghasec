package unlockedtransitiveaction

import (
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unlocked-transitive-action"

// Rule checks that the actions used inside the actions a locked workflow runs
// are recorded in its dependency lockfile.
type Rule struct {
	Fetcher rules.ActionFileFetcher
}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return true }

func (r *Rule) Why() string {
	return "GitHub resolves an action used inside a locked action from that action's entry in the lockfile or from the workflow's list, and fails the job when neither records it"
}

func (r *Rule) Fix() string {
	return "Run `gh actions-lock` to update the lockfile"
}

// CheckWorkflow reports, for each step of a locked workflow whose action the
// lockfile locks, the actions used inside it that the lockfile records neither
// in the parent action's entry nor in the workflow's list. An action file
// cannot be locked, so the rule does not check action files. A step's action
// the lockfile does not record is left to unlocked-action, and an action that
// cannot be fetched to unpinned-transitive-action, which reports the error.
func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	lock := mapping.Lock
	if !lock.Locked() {
		return nil
	}
	return rules.CollectStepErrors(mapping.EachStep, func(step workflow.StepMapping) []*diagnostic.Error {
		ref, ok := step.Uses()
		if !ok {
			return nil
		}
		root, ok := rules.StepRemoteAction(ref, lock)
		if !ok {
			return nil
		}

		var errs []*diagnostic.Error
		// Recording an action in the workflow's list covers every place it is
		// used under the step, so it is reported once, where it is first reached.
		reported := map[string]bool{}
		rules.WalkTransitive(r.Fetcher, root, lock, rules.TransitiveVisitor{
			Uses: func(parent rules.RemoteAction, inner workflow.ActionRef, via []string) {
				if inner.IsDocker() || reported[inner.String()] || lock.ListedFrom(parent.Dep, inner.String()) {
					return
				}
				reported[inner.String()] = true
				errs = append(errs, &diagnostic.Error{
					Token:   ref.Token(),
					Message: rules.TransitiveMessage(ref, "unlocked action", inner.String(), via),
				})
			},
		})
		return errs
	})
}
