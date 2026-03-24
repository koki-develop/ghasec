package missingsharefcomment

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/git"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "missing-sha-ref-comment"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		if err := checkStepAction(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		if err := checkStepAction(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func checkStepAction(step workflow.StepMapping) *diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if ref.IsLocal() || ref.IsDocker() {
		return nil
	}

	if !ref.Ref().IsFullSHA() {
		return nil
	}

	tk := ref.Token()
	if tk.Next != nil && tk.Next.Type == token.CommentType {
		comment := strings.TrimSpace(tk.Next.Value)
		if comment != "" && git.Ref(comment).IsValid() {
			return nil
		}
	}

	return &diagnostic.Error{
		Token:   ref.Token(),
		Message: fmt.Sprintf("%q must have an inline comment with a ref", ref.String()),
	}
}
