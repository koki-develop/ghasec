package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

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
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"jobs\" must be a mapping, but got %s", kv.Value.Type()),
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
				Message: fmt.Sprintf("job %q must be a mapping, but got %s", jobEntry.Key.GetToken().Value, jobEntry.Value.Type()),
			})
			continue
		}
		errs = append(errs, checkJob(jobEntry.Key.GetToken(), workflow.JobMapping{Mapping: workflow.Mapping{MappingNode: jobMapping}})...)
	}
	return errs
}

func checkJob(jobKey *token.Token, job workflow.JobMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	runsOnKV := job.FindKey("runs-on")
	usesKV := job.FindKey("uses")
	stepsKV := job.FindKey("steps")

	hasRunsOn := runsOnKV != nil
	hasUses := usesKV != nil
	hasSteps := stepsKV != nil

	if !hasRunsOn && !hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: "\"runs-on\" or \"uses\" is required",
		})
	}
	if hasRunsOn && hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: "\"runs-on\" and \"uses\" are mutually exclusive",
			Markers: []*token.Token{runsOnKV.Key.GetToken(), usesKV.Key.GetToken()},
		})
	}
	if hasUses && hasSteps {
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: "\"uses\" and \"steps\" are mutually exclusive",
			Markers: []*token.Token{usesKV.Key.GetToken(), stepsKV.Key.GetToken()},
		})
	}

	// Unknown key check (uses union set to avoid duplication with mutual-exclusivity checks)
	for _, entry := range job.Values {
		key := entry.Key.GetToken().Value
		if !allJobKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("unknown key %q", key),
			})
		}
	}

	if hasRunsOn {
		errs = append(errs, checkRunsOn(runsOnKV)...)
	}
	if hasSteps {
		errs = append(errs, checkStepsType(stepsKV)...)
	}
	if hasUses {
		errs = append(errs, checkUsesType(usesKV)...)
	}

	// Strategy check
	strategyKV := job.FindKey("strategy")
	if strategyKV != nil {
		errs = append(errs, checkStrategy(strategyKV)...)
	}

	// Concurrency check
	concurrencyKV := job.FindKey("concurrency")
	if concurrencyKV != nil {
		errs = append(errs, checkConcurrencyMapping(concurrencyKV)...)
	}

	// Defaults check
	defaultsKV := job.FindKey("defaults")
	if defaultsKV != nil {
		errs = append(errs, checkDefaults(defaultsKV)...)
	}

	// Permissions check
	permissionsKV := job.FindKey("permissions")
	if permissionsKV != nil {
		errs = append(errs, checkPermissions(permissionsKV)...)
	}

	// Step validation (when steps is a valid sequence)
	if hasSteps {
		if seq, ok := stepsKV.Value.(*ast.SequenceNode); ok {
			errs = append(errs, checkStepEntries(seq)...)
		}
	}

	return errs
}

func checkRunsOn(kv *ast.MappingValueNode) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}

	switch v := kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	case *ast.SequenceNode:
		return checkRunsOnSequence(v)
	case *ast.MappingNode:
		return checkRunsOnMapping(v)
	default:
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"runs-on\" must be a string, sequence, or mapping, but got %s", kv.Value.Type()),
		}}
	}
}

func checkRunsOnMapping(m *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range m.Values {
		key := entry.Key.GetToken().Value
		if !knownRunsOnKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:   entry.Key.GetToken(),
				Message: fmt.Sprintf("\"runs-on\" has unknown key %q; valid keys are \"group\" and \"labels\"", key),
			})
		}
	}
	return errs
}

func checkRunsOnSequence(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, elem := range seq.Values {
		if isExpression(elem) {
			continue
		}
		switch elem.(type) {
		case *ast.StringNode, *ast.LiteralNode:
			// ok
		default:
			errs = append(errs, &diagnostic.Error{
				Token:   elem.GetToken(),
				Message: fmt.Sprintf("\"runs-on\" elements must be strings, but got %s", elem.Type()),
			})
		}
	}
	return errs
}

func checkStepsType(kv *ast.MappingValueNode) []*diagnostic.Error {
	_, ok := kv.Value.(*ast.SequenceNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"steps\" must be a sequence, but got %s", kv.Value.Type()),
		}}
	}
	return nil
}

func checkUsesType(kv *ast.MappingValueNode) []*diagnostic.Error {
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	default:
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"uses\" must be a string, but got %s", kv.Value.Type()),
		}}
	}
}

func checkStrategy(kv *ast.MappingValueNode) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}

	strategyMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"strategy\" must be a mapping, but got %s", kv.Value.Type()),
		}}
	}

	matrixKV := workflow.Mapping{MappingNode: strategyMapping}.FindKey("matrix")
	if matrixKV == nil {
		return []*diagnostic.Error{{
			Token:   kv.Key.GetToken(),
			Message: "\"matrix\" is required",
		}}
	}
	return nil
}
