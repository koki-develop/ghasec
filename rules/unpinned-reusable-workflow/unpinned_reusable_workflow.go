package unpinnedreusableworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unpinned-reusable-workflow"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Git tags and branches are mutable. Reusable workflows execute with secrets the caller passes in, so a compromised upstream that moves a tag can run malicious code with access to those secrets on the next run"
}

func (r *Rule) Fix() string {
	return "Pin to the full 40-character commit SHA. Add the version as an inline comment to keep it human-readable"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectJobError(mapping.EachJob, checkJob)
}

func checkJob(_ *token.Token, job workflow.JobMapping) *diagnostic.Error {
	ref, ok := job.Uses()
	if !ok {
		return nil
	}
	if ref.IsLocal() {
		return nil
	}
	if ref.Ref() == "" {
		return nil
	}
	if ref.Ref().IsFullSHA() {
		return nil
	}
	return &diagnostic.Error{
		Token:   ref.RefToken(),
		Message: fmt.Sprintf("%q must be pinned to a full length commit SHA", ref.String()),
	}
}
