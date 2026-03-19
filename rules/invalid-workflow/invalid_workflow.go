package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-workflow"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Check(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	fileStart := mapping.FirstToken()

	var errs []*diagnostic.Error
	errs = append(errs, checkOn(mapping.Mapping, fileStart)...)

	jobsMapping, jobsErrs := checkJobs(mapping.Mapping, fileStart)
	errs = append(errs, jobsErrs...)

	if jobsMapping != nil {
		errs = append(errs, checkJobEntries(jobsMapping)...)
	}

	return errs
}

func checkOn(mapping workflow.Mapping, fileStart *token.Token) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return []*diagnostic.Error{{
			Token:   fileStart,
			Message: "\"on\" is required",
		}}
	}

	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	case *ast.SequenceNode:
		return nil
	case *ast.MappingNode:
		return nil
	default:
		return []*diagnostic.Error{{
			Token:       kv.Value.GetToken(),
			BeforeToken: kv.Key.GetToken(),
			Message:     fmt.Sprintf("\"on\" must be a string, sequence, or mapping, but got %s", kv.Value.Type()),
		}}
	}
}

func checkJobs(mapping workflow.Mapping, fileStart *token.Token) (*ast.MappingNode, []*diagnostic.Error) {
	kv := mapping.FindKey("jobs")
	if kv == nil {
		return nil, []*diagnostic.Error{{
			Token:   fileStart,
			Message: "\"jobs\" is required",
		}}
	}

	if _, ok := kv.Value.(*ast.NullNode); ok {
		return nil, []*diagnostic.Error{{
			Token:   kv.Key.GetToken(),
			Message: "\"jobs\" must not be empty",
		}}
	}

	jobsMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return nil, []*diagnostic.Error{{
			Token:       kv.Value.GetToken(),
			BeforeToken: kv.Key.GetToken(),
			Message:     "\"jobs\" must be a mapping",
		}}
	}

	return jobsMapping, nil
}

func checkJobEntries(jobs *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, jobEntry := range jobs.Values {
		jobMapping, ok := jobEntry.Value.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:       jobEntry.Value.GetToken(),
				BeforeToken: jobEntry.Key.GetToken(),
				Message:     fmt.Sprintf("job %q must be a mapping", jobEntry.Key.GetToken().Value),
			})
			continue
		}
		errs = append(errs, checkJob(jobEntry.Key.GetToken(), workflow.JobMapping{Mapping: workflow.Mapping{MappingNode: jobMapping}})...)
	}
	return errs
}

func checkJob(jobKey *token.Token, job workflow.JobMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	jobID := jobKey.Value

	runsOnKV := job.FindKey("runs-on")
	usesKV := job.FindKey("uses")
	stepsKV := job.FindKey("steps")

	hasRunsOn := runsOnKV != nil
	hasUses := usesKV != nil
	hasSteps := stepsKV != nil

	if !hasRunsOn && !hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:       job.GetToken(),
			BeforeToken: jobKey,
			Message:     fmt.Sprintf("job %q must have either \"runs-on\" or \"uses\"", jobID),
		})
	}
	if hasRunsOn && hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: fmt.Sprintf("job %q cannot have both \"runs-on\" and \"uses\"", jobID),
			Markers: []*token.Token{runsOnKV.Key.GetToken(), usesKV.Key.GetToken()},
		})
	}
	if hasUses && hasSteps {
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: fmt.Sprintf("job %q cannot have both \"uses\" and \"steps\"", jobID),
			Markers: []*token.Token{usesKV.Key.GetToken(), stepsKV.Key.GetToken()},
		})
	}

	if hasRunsOn {
		errs = append(errs, checkRunsOn(jobID, runsOnKV)...)
	}
	if hasSteps {
		errs = append(errs, checkSteps(jobID, stepsKV)...)
	}
	if hasUses {
		errs = append(errs, checkUses(jobID, usesKV)...)
	}

	return errs
}

func checkRunsOn(jobID string, kv *ast.MappingValueNode) []*diagnostic.Error {
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	case *ast.SequenceNode:
		return nil
	case *ast.MappingNode:
		return nil
	default:
		return []*diagnostic.Error{{
			Token:       kv.Value.GetToken(),
			BeforeToken: kv.Key.GetToken(),
			Message:     fmt.Sprintf("job %q \"runs-on\" must be a string, sequence, or mapping, but got %s", jobID, kv.Value.Type()),
		}}
	}
}

func checkSteps(jobID string, kv *ast.MappingValueNode) []*diagnostic.Error {
	_, ok := kv.Value.(*ast.SequenceNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:       kv.Value.GetToken(),
			BeforeToken: kv.Key.GetToken(),
			Message:     fmt.Sprintf("job %q \"steps\" must be a sequence, but got %s", jobID, kv.Value.Type()),
		}}
	}
	return nil
}

func checkUses(jobID string, kv *ast.MappingValueNode) []*diagnostic.Error {
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	default:
		return []*diagnostic.Error{{
			Token:       kv.Value.GetToken(),
			BeforeToken: kv.Key.GetToken(),
			Message:     fmt.Sprintf("job %q \"uses\" must be a string, but got %s", jobID, kv.Value.Type()),
		}}
	}
}
