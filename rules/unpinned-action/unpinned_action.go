package unpinnedaction

import (
	"fmt"

	"github.com/koki-develop/ghasec/diagnostic"
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
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		if err := checkStepAction(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		if err := checkStepAction(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func checkStepAction(step workflow.StepMapping) *diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if ref.IsLocal() || ref.IsDocker() {
		return nil
	}

	if ref.Ref() == "" {
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
