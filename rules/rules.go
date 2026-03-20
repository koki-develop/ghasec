package rules

import (
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

// Rule defines common metadata for all validation rules.
type Rule interface {
	ID() string
	Required() bool
	Online() bool
}

// WorkflowRule validates workflow files (.github/workflows/*.yml|yaml).
type WorkflowRule interface {
	Rule
	CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error
}

// ActionRule validates action metadata files (action.yml|yaml).
type ActionRule interface {
	Rule
	CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error
}
