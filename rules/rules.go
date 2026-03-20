package rules

import (
	"fmt"

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
// CheckWorkflow must be safe for concurrent use from multiple goroutines.
type WorkflowRule interface {
	Rule
	CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error
}

// ActionRule validates action metadata files (action.yml|yaml).
// CheckAction must be safe for concurrent use from multiple goroutines.
type ActionRule interface {
	Rule
	CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error
}

// CheckUnknownKeys reports an error for each mapping entry whose key is not
// present in knownKeys.
func CheckUnknownKeys(mapping workflow.Mapping, knownKeys map[string]bool) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range mapping.Values {
		key := entry.Key.GetToken().Value
		if !knownKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("unknown key %q", key),
			})
		}
	}
	return errs
}
