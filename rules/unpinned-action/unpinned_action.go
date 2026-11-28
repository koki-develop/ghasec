package unpinnedaction

import (
	"fmt"
	"regexp"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unpinned-action"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Git tags and branches are mutable. A compromised upstream can move a tag to point to malicious code, executing it silently on the next run"
}

func (r *Rule) Fix() string {
	return "Pin to the full 40-character commit SHA. Add the version as an inline comment to keep it human-readable"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	// GitHub runs every action a locked workflow uses at the commit its
	// lockfile records, and refuses to start the run when one is not recorded,
	// so a tag there is not mutable.
	locked := mapping.Lock.Locked()
	return rules.CollectStepError(mapping.EachStep, func(step workflow.StepMapping) *diagnostic.Error {
		err := checkStepAction(step, locked)
		if err != nil && err.Fix == "" {
			// A workflow, unlike an action, can also be locked.
			err.Fix = workflowFix
		}
		return err
	})
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepError(mapping.EachStep, func(step workflow.StepMapping) *diagnostic.Error {
		return checkStepAction(step, false)
	})
}

// workflowFix is the fix for an action reference in a workflow, which a
// dependency lockfile can lock as well as a SHA can pin.
var workflowFix = (&Rule{}).Fix() + ". Alternatively, lock the workflow's actions in .github/workflows/actions.lock"

var sha256DigestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// checkStepAction checks a step's uses value. locked reports whether a
// lockfile locks the step's workflow, which covers every remote action ref but
// not Docker images.
func checkStepAction(step workflow.StepMapping, locked bool) *diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if ref.IsDocker() {
		if sha256DigestRe.MatchString(ref.String()) {
			return nil
		}
		return &diagnostic.Error{
			Token:   ref.Token(),
			Message: fmt.Sprintf("%q must be pinned to a digest", ref.String()),
			Why:     "Docker image tags are mutable. A compromised or updated registry image can change the contents behind a tag, executing different code silently on the next run",
			Fix:     "Pin to the image digest using the @sha256:... suffix. Keep the tag for human readability",
		}
	}

	if locked || !ref.IsRemote() || ref.Ref() == "" {
		return nil
	}

	if !ref.Ref().IsFullSHA() {
		return &diagnostic.Error{
			Token:   ref.RefToken(),
			Message: fmt.Sprintf("%q must be pinned to a full length commit SHA", ref.String()),
		}
	}

	return nil
}
