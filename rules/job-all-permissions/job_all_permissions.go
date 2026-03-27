package joballpermissions

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "job-all-permissions"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "read-all or write-all at the job level grants broad permissions, undoing the protection of a locked-down workflow-level permissions: {}"
}

func (r *Rule) Fix() string {
	return "Declare individual permission scopes that the job actually needs instead of read-all or write-all"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectJobError(mapping.EachJob, checkJob)
}

func checkJob(_ *token.Token, job workflow.JobMapping) *diagnostic.Error {
	permKV := job.FindKey("permissions")
	if permKV == nil {
		return nil
	}
	return checkPermissionsValue(permKV.Value)
}

func checkPermissionsValue(node ast.Node) *diagnostic.Error {
	var value string
	switch v := rules.UnwrapNode(node).(type) {
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
		Token:   rules.UnwrapNode(node).GetToken(),
		Message: fmt.Sprintf(`"permissions" must not be %q; grant individual scopes instead`, value),
	}
}
