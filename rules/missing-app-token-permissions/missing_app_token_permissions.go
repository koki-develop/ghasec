package missingapptokenpermissions

import (
	"strings"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "missing-app-token-permissions"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Without explicit permission-* inputs, the token inherits every permission the GitHub App installation has. A compromised downstream step can exploit this over-privileged token"
}

func (r *Rule) Fix() string {
	return "Add one or more permission-* inputs to the with section to request only the permissions needed (e.g., permission-contents: read)"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectStepError(mapping.EachStep, checkStep)
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepError(mapping.EachStep, checkStep)
}

func checkStep(step workflow.StepMapping) *diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if !strings.HasPrefix(ref.String(), "actions/create-github-app-token@") {
		return nil
	}

	if withMapping, ok := step.With(); ok {
		for _, entry := range withMapping.Values {
			if strings.HasPrefix(entry.Key.GetToken().Value, "permission-") {
				return nil
			}
		}
	}

	return &diagnostic.Error{
		Token:   ref.Token(),
		Message: `"permission-*" input must be set in "with"`,
	}
}
