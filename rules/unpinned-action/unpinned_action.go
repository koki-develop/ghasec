package unpinnedaction

import (
	"fmt"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unpinned-action"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Check(mapping workflow.WorkflowMapping) []*diagnostic.Error {
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

	if !ref.Ref().IsFullSHA() {
		return &diagnostic.Error{
			Token:         ref.RefToken(),
			ContextTokens: []*token.Token{step.JobsKeyToken(), step.JobKeyToken(), step.StepsKeyToken(), step.SeqEntryToken()},
			Message:       fmt.Sprintf("%q must be pinned to a full length commit SHA", ref.String()),
		}
	}

	return nil
}
