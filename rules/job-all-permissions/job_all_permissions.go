package joballpermissions

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "job-all-permissions"

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
		permKV := workflow.Mapping{MappingNode: jobMapping}.FindKey("permissions")
		if permKV == nil {
			continue
		}
		if err := checkPermissionsValue(permKV.Value); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func checkPermissionsValue(node ast.Node) *diagnostic.Error {
	var value string
	switch v := node.(type) {
	case *ast.StringNode:
		value = v.Value
	case *ast.LiteralNode:
		value = v.Value.Value
	default:
		return nil
	}

	if value != "read-all" && value != "write-all" {
		return nil
	}

	return &diagnostic.Error{
		Token:   node.GetToken(),
		Message: fmt.Sprintf(`"permissions" must not be %q; grant individual scopes instead`, value),
	}
}
