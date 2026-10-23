package workspacerelativeaction

import (
	"fmt"
	"strings"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "workspace-relative-action"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "A ./ reference runs whatever action is in the runner's workspace, not the repository at the running commit. Any earlier step that changes the workspace, such as checking out pull request code or cloning another repository, controls which code runs, and actions policies never restrict actions on the runner filesystem. In a composite action, ./ resolves against the caller's workspace instead of the action's own repository"
}

func (r *Rule) Fix() string {
	return "Replace ./ with $/ to run the action from the same repository at the running commit. If the action comes from another repository checked out into the workspace, reference it as {owner}/{repo}@{ref} when possible"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectStepError(mapping.EachStep, checkStep)
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepError(mapping.EachStep, checkStep)
}

func checkStep(step workflow.StepMapping) *diagnostic.Error {
	ref, ok := step.Uses()
	if !ok || !ref.IsLocal() {
		return nil
	}
	return &diagnostic.Error{
		Token:   ref.Token(),
		Message: fmt.Sprintf("%q must be referenced as %q", ref.String(), workflow.SelfRepositoryPrefix+strings.TrimPrefix(ref.String(), "./")),
	}
}
