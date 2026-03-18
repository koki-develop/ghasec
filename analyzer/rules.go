package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
)

func findKey(mapping *ast.MappingNode, key string) *ast.MappingValueNode {
	for _, v := range mapping.Values {
		if v.Key.GetToken().Value == key {
			return v
		}
	}
	return nil
}

func topLevelMapping(doc *ast.DocumentNode) *ast.MappingNode {
	if doc.Body == nil {
		return nil
	}
	m, ok := doc.Body.(*ast.MappingNode)
	if !ok {
		return nil
	}
	return m
}

func checkJobs(mapping *ast.MappingNode) (*ast.MappingNode, []*DiagnosticError) {
	kv := findKey(mapping, "jobs")
	if kv == nil {
		return nil, []*DiagnosticError{{
			Token:   mapping.GetToken(),
			Message: "\"jobs\" is required",
		}}
	}

	if _, ok := kv.Value.(*ast.NullNode); ok {
		return nil, []*DiagnosticError{{
			Token:   kv.Key.GetToken(),
			Message: "\"jobs\" must not be empty",
		}}
	}

	jobsMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return nil, []*DiagnosticError{{
			Token:   kv.Value.GetToken(),
			Message: "\"jobs\" must be a mapping",
		}}
	}

	return jobsMapping, nil
}

func checkJobEntries(jobs *ast.MappingNode) []*DiagnosticError {
	var errs []*DiagnosticError
	for _, jobEntry := range jobs.Values {
		jobMapping, ok := jobEntry.Value.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &DiagnosticError{
				Token:   jobEntry.Value.GetToken(),
				Message: fmt.Sprintf("job %q must be a mapping", jobEntry.Key.GetToken().Value),
			})
			continue
		}
		errs = append(errs, checkJob(jobEntry.Key.GetToken().Value, jobMapping)...)
	}
	return errs
}

func checkJob(jobID string, job *ast.MappingNode) []*DiagnosticError {
	var errs []*DiagnosticError

	runsOnKV := findKey(job, "runs-on")
	usesKV := findKey(job, "uses")
	stepsKV := findKey(job, "steps")

	hasRunsOn := runsOnKV != nil
	hasUses := usesKV != nil
	hasSteps := stepsKV != nil

	if !hasRunsOn && !hasUses {
		errs = append(errs, &DiagnosticError{
			Token:   job.GetToken(),
			Message: fmt.Sprintf("job %q must have either \"runs-on\" or \"uses\"", jobID),
		})
	}
	if hasRunsOn && hasUses {
		errs = append(errs, &DiagnosticError{
			Token:   job.GetToken(),
			Message: fmt.Sprintf("job %q cannot have both \"runs-on\" and \"uses\"", jobID),
		})
	}
	if hasUses && hasSteps {
		errs = append(errs, &DiagnosticError{
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

func checkRunsOn(jobID string, kv *ast.MappingValueNode) []*DiagnosticError {
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	case *ast.SequenceNode:
		return nil
	case *ast.MappingNode:
		return nil
	default:
		return []*DiagnosticError{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("job %q \"runs-on\" must be a string, sequence, or mapping, but got %s", jobID, kv.Value.Type()),
		}}
	}
}

func checkSteps(jobID string, kv *ast.MappingValueNode) []*DiagnosticError {
	seq, ok := kv.Value.(*ast.SequenceNode)
	if !ok {
		return []*DiagnosticError{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("job %q \"steps\" must be a sequence, but got %s", jobID, kv.Value.Type()),
		}}
	}

	var errs []*DiagnosticError
	for _, step := range seq.Values {
		stepMapping, ok := step.(*ast.MappingNode)
		if !ok {
			continue
		}
		errs = append(errs, checkStepAction(stepMapping)...)
	}
	return errs
}

var fullSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func checkStepAction(step *ast.MappingNode) []*DiagnosticError {
	usesKV := findKey(step, "uses")
	if usesKV == nil {
		return nil
	}

	var usesValue string
	switch v := usesKV.Value.(type) {
	case *ast.StringNode:
		usesValue = v.Value
	case *ast.LiteralNode:
		usesValue = v.Value.Value
	default:
		return nil
	}

	// Skip local actions and Docker actions
	if strings.HasPrefix(usesValue, "./") || strings.HasPrefix(usesValue, "docker://") {
		return nil
	}

	// Remote action: must be pinned to a full commit SHA
	atIdx := strings.LastIndex(usesValue, "@")
	if atIdx == -1 || !fullSHAPattern.MatchString(usesValue[atIdx+1:]) {
		return []*DiagnosticError{{
			Token:   usesKV.Value.GetToken(),
			Message: fmt.Sprintf("action %q must be pinned to a full length commit SHA", usesValue),
		}}
	}

	return nil
}

func checkUses(jobID string, kv *ast.MappingValueNode) []*DiagnosticError {
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	default:
		return []*DiagnosticError{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("job %q \"uses\" must be a string, but got %s", jobID, kv.Value.Type()),
		}}
	}
}

func checkOn(mapping *ast.MappingNode) []*DiagnosticError {
	kv := findKey(mapping, "on")
	if kv == nil {
		return []*DiagnosticError{{
			Token:   mapping.GetToken(),
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
		return []*DiagnosticError{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"on\" must be a string, sequence, or mapping, but got %s", kv.Value.Type()),
		}}
	}
}
