package workflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

const id = "invalid-workflow"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }

func (r *Rule) Check(f *ast.File) []*diagnostic.Error {
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		tk := &token.Token{
			Position: &token.Position{
				Line:   1,
				Column: 1,
				Offset: 1,
			},
			Value: " ",
		}
		return []*diagnostic.Error{
			{Token: tk, Message: "\"on\" is required"},
			{Token: tk, Message: "\"jobs\" is required"},
		}
	}

	mapping := rules.TopLevelMapping(f.Docs[0])
	if mapping == nil {
		return []*diagnostic.Error{{
			Token:   f.Docs[0].Body.GetToken(),
			Message: "workflow must be a mapping",
		}}
	}

	fileStart := firstToken(f.Docs[0].Body.GetToken())

	var errs []*diagnostic.Error
	errs = append(errs, checkOn(mapping, fileStart)...)

	jobsMapping, jobsErrs := checkJobs(mapping, fileStart)
	errs = append(errs, jobsErrs...)

	if jobsMapping != nil {
		errs = append(errs, checkJobEntries(jobsMapping)...)
	}

	return errs
}

func checkOn(mapping *ast.MappingNode, fileStart *token.Token) []*diagnostic.Error {
	kv := rules.FindKey(mapping, "on")
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
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"on\" must be a string, sequence, or mapping, but got %s", kv.Value.Type()),
		}}
	}
}

func checkJobs(mapping *ast.MappingNode, fileStart *token.Token) (*ast.MappingNode, []*diagnostic.Error) {
	kv := rules.FindKey(mapping, "jobs")
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
			Token:   kv.Value.GetToken(),
			Message: "\"jobs\" must be a mapping",
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
				Token:   jobEntry.Value.GetToken(),
				Message: fmt.Sprintf("job %q must be a mapping", jobEntry.Key.GetToken().Value),
			})
			continue
		}
		errs = append(errs, checkJob(jobEntry.Key.GetToken().Value, jobMapping)...)
	}
	return errs
}

func checkJob(jobID string, job *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error

	runsOnKV := rules.FindKey(job, "runs-on")
	usesKV := rules.FindKey(job, "uses")
	stepsKV := rules.FindKey(job, "steps")

	hasRunsOn := runsOnKV != nil
	hasUses := usesKV != nil
	hasSteps := stepsKV != nil

	if !hasRunsOn && !hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:   job.GetToken(),
			Message: fmt.Sprintf("job %q must have either \"runs-on\" or \"uses\"", jobID),
		})
	}
	if hasRunsOn && hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:   job.GetToken(),
			Message: fmt.Sprintf("job %q cannot have both \"runs-on\" and \"uses\"", jobID),
		})
	}
	if hasUses && hasSteps {
		errs = append(errs, &diagnostic.Error{
			Token:   job.GetToken(),
			Message: fmt.Sprintf("job %q cannot have both \"uses\" and \"steps\"", jobID),
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
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("job %q \"runs-on\" must be a string, sequence, or mapping, but got %s", jobID, kv.Value.Type()),
		}}
	}
}

func checkSteps(jobID string, kv *ast.MappingValueNode) []*diagnostic.Error {
	_, ok := kv.Value.(*ast.SequenceNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("job %q \"steps\" must be a sequence, but got %s", jobID, kv.Value.Type()),
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
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("job %q \"uses\" must be a string, but got %s", jobID, kv.Value.Type()),
		}}
	}
}

func firstToken(tk *token.Token) *token.Token {
	for tk.Prev != nil {
		tk = tk.Prev
	}
	cp := *tk
	cp.Value = string(tk.Value[0])
	return &cp
}
