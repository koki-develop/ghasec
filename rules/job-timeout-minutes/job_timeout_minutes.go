package jobtimeoutminutes

import (
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "job-timeout-minutes"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Jobs default to a 360-minute timeout. Without an explicit timeout, a compromised step has a large window to exfiltrate data or pivot into the internal network, especially on self-hosted runners"
}

func (r *Rule) Fix() string {
	return "Set timeout-minutes to an appropriate value for the expected runtime"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectJobError(mapping.EachJob, checkJob)
}

func checkJob(jobKeyToken *token.Token, job workflow.JobMapping) *diagnostic.Error {
	if job.FindKey("uses") != nil {
		return nil
	}
	if job.FindKey("timeout-minutes") == nil {
		return &diagnostic.Error{
			Token:   jobKeyToken,
			Message: `"timeout-minutes" must be set`,
		}
	}
	return nil
}
