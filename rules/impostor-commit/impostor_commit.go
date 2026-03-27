package impostorcommit

import (
	"context"
	"fmt"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "impostor-commit"

// CommitVerifier checks whether a commit SHA is reachable from any branch or
// tag in the given repository.
type CommitVerifier interface {
	VerifyCommit(ctx context.Context, owner, repo, sha string) (bool, error)
}

type Rule struct {
	Verifier CommitVerifier
}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return true }

func (r *Rule) Why() string {
	return "GitHub shares object storage across forks. An attacker can reference a malicious fork commit using the original repository's namespace, and the SHA resolves successfully"
}

func (r *Rule) Fix() string {
	return "Verify the commit belongs to the referenced repository's history and update the SHA accordingly"
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

	if !ref.Ref().IsFullSHA() {
		return nil
	}

	owner, repo := ref.OwnerRepo()
	if owner == "" {
		return nil
	}

	sha := string(ref.Ref())
	reachable, err := r.Verifier.VerifyCommit(context.Background(), owner, repo, sha)
	if err != nil {
		return []*diagnostic.Error{{
			Token:   ref.RefToken(),
			Message: fmt.Sprintf("failed to verify commit for %q: %v", ref.String(), err),
		}}
	}

	if !reachable {
		return []*diagnostic.Error{{
			Token:   ref.RefToken(),
			Message: fmt.Sprintf("commit must belong to %s/%s", owner, repo),
		}}
	}

	return nil
}
