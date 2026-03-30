package archivedaction

import (
	"context"
	"fmt"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "archived-action"

// ArchiveChecker checks whether a repository is archived.
type ArchiveChecker interface {
	IsArchived(ctx context.Context, owner, repo string) (bool, error)
}

type Rule struct {
	Checker ArchiveChecker
}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return true }

func (r *Rule) Why() string {
	return "Archived repositories no longer receive security patches, bug fixes, or dependency updates. Using them exposes workflows to known and future vulnerabilities that will never be addressed"
}

func (r *Rule) Fix() string {
	return "Migrate to an actively maintained alternative action that provides the same functionality"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectStepErrors(mapping.EachStep, r.checkStep)
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return rules.CollectStepErrors(mapping.EachStep, r.checkStep)
}

func (r *Rule) checkStep(step workflow.StepMapping) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if ref.IsLocal() || ref.IsDocker() {
		return nil
	}

	owner, repo := ref.OwnerRepo()
	if owner == "" {
		return nil
	}

	archived, err := r.Checker.IsArchived(context.Background(), owner, repo)
	if err != nil {
		return []*diagnostic.Error{{
			Token:   ref.Token(),
			Message: fmt.Sprintf("failed to check archive status for %q: %v", owner+"/"+repo, err),
		}}
	}

	if archived {
		return []*diagnostic.Error{{
			Token:   ref.Token(),
			Message: fmt.Sprintf("%q is archived and must not be used", owner+"/"+repo),
		}}
	}

	return nil
}
