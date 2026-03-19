package rules

import (
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

// Rule defines the interface for workflow validation rules.
type Rule interface {
	ID() string
	Required() bool
	Online() bool
	Check(mapping workflow.WorkflowMapping) []*diagnostic.Error
}
