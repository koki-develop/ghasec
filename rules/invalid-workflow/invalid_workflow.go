package invalidworkflow

import (
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-workflow"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	fileStart := mapping.FirstToken()

	var errs []*diagnostic.Error

	errs = append(errs, checkTopLevelKeys(mapping.Mapping)...)
	errs = append(errs, checkOn(mapping.Mapping, fileStart)...)

	// Top-level permissions
	if permKV := mapping.FindKey("permissions"); permKV != nil {
		errs = append(errs, checkPermissions(permKV)...)
	}

	// Top-level concurrency
	if concurrencyKV := mapping.FindKey("concurrency"); concurrencyKV != nil {
		errs = append(errs, checkConcurrencyMapping(concurrencyKV)...)
	}

	// Top-level defaults
	if defaultsKV := mapping.FindKey("defaults"); defaultsKV != nil {
		errs = append(errs, checkDefaults(defaultsKV)...)
	}

	jobsMapping, jobsErrs := checkJobs(mapping.Mapping, fileStart)
	errs = append(errs, jobsErrs...)

	if jobsMapping != nil {
		jobsKeyToken := mapping.FindKey("jobs").Key.GetToken()
		errs = append(errs, checkJobEntries(jobsMapping, jobsKeyToken)...)
	}

	return errs
}
