package jobtimeoutminutes

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "job-timeout-minutes"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	jobsKV := mapping.FindKey("jobs")
	if jobsKV == nil {
		return nil
	}
	jobsMapping, ok := jobsKV.Value.(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	for _, jobEntry := range jobsMapping.Values {
		jobMapping, ok := jobEntry.Value.(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: jobMapping}
		if m.FindKey("uses") != nil {
			continue
		}
		if m.FindKey("timeout-minutes") == nil {
			errs = append(errs, &diagnostic.Error{
				Token:   jobEntry.Key.GetToken(),
				Message: `"timeout-minutes" must be set`,
			})
		}
	}
	return errs
}
