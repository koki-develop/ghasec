package secretsinherit

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "secrets-inherit"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "`secrets: inherit` passes all of the caller's secrets to the reusable workflow, violating the principle of least privilege. If the called workflow is compromised or contains a vulnerability, every secret is exposed — not just the ones the workflow actually needs"
}

func (r *Rule) Fix() string {
	return "Replace `secrets: inherit` with an explicit `secrets` mapping that passes only the specific secrets the reusable workflow requires"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	jobsKV := mapping.FindKey("jobs")
	if jobsKV == nil {
		return nil
	}
	jobsMapping, ok := rules.UnwrapNode(jobsKV.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	for _, jobEntry := range jobsMapping.Values {
		jobMapping, ok := rules.UnwrapNode(jobEntry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: jobMapping}
		secretsKV := m.FindKey("secrets")
		if secretsKV == nil {
			continue
		}
		if rules.IsString(secretsKV.Value) && rules.StringValue(secretsKV.Value) == "inherit" {
			errs = append(errs, &diagnostic.Error{
				Token:   secretsKV.Value.GetToken(),
				Message: fmt.Sprintf("job %q must not use `secrets: inherit`", jobEntry.Key.GetToken().Value),
			})
		}
	}
	return errs
}
