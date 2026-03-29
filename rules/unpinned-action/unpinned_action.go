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
	return rules.CollectStepError(mapping.EachStep, checkStepAction)
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepError(mapping.EachStep, checkStepAction)
}

var sha256DigestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

func checkStepAction(step workflow.StepMapping) *diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if ref.IsLocal() {
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
