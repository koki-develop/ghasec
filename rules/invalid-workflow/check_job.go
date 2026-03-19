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
			Token:         kv.Value.GetToken(),
			ContextTokens: []*token.Token{kv.Key.GetToken()},
			Message:       "\"jobs\" must be a mapping",
		}}
	}

	return jobsMapping, nil
}

func checkJobEntries(jobs *ast.MappingNode, jobsKeyToken *token.Token) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, jobEntry := range jobs.Values {
		jobMapping, ok := jobEntry.Value.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:         jobEntry.Value.GetToken(),
				ContextTokens: []*token.Token{jobsKeyToken, jobEntry.Key.GetToken()},
				Message:       fmt.Sprintf("job %q must be a mapping", jobEntry.Key.GetToken().Value),
			})
			continue
		}
		errs = append(errs, checkJob(jobsKeyToken, jobEntry.Key.GetToken(), workflow.JobMapping{Mapping: workflow.Mapping{MappingNode: jobMapping}})...)
	}
	return errs
}

func checkJob(jobsKeyToken *token.Token, jobKey *token.Token, job workflow.JobMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	jobID := jobKey.Value
	jobCtx := []*token.Token{jobsKeyToken}
	jobKeyCtx := []*token.Token{jobsKeyToken, jobKey}

	runsOnKV := job.FindKey("runs-on")
	usesKV := job.FindKey("uses")
	stepsKV := job.FindKey("steps")

	hasRunsOn := runsOnKV != nil
	hasUses := usesKV != nil
	hasSteps := stepsKV != nil

	if !hasRunsOn && !hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:         jobKey,
			ContextTokens: jobCtx,
			Message:       fmt.Sprintf("job %q must have either \"runs-on\" or \"uses\"", jobID),
		})
	}
	if hasRunsOn && hasUses {
		errs = append(errs, &diagnostic.Error{
			Token:         jobKey,
			ContextTokens: jobCtx,
			Message:       fmt.Sprintf("job %q cannot have both \"runs-on\" and \"uses\"", jobID),
			Markers:       []*token.Token{runsOnKV.Key.GetToken(), usesKV.Key.GetToken()},
		})
	}
	if hasUses && hasSteps {
		errs = append(errs, &diagnostic.Error{
			Token:         jobKey,
			ContextTokens: jobCtx,
			Message:       fmt.Sprintf("job %q cannot have both \"uses\" and \"steps\"", jobID),
			Markers:       []*token.Token{usesKV.Key.GetToken(), stepsKV.Key.GetToken()},
		})
	}

	// Unknown key check (uses union set to avoid duplication with mutual-exclusivity checks)
	for _, entry := range job.Values {
		key := entry.Key.GetToken().Value
		if !allJobKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:         entry.Key.GetToken(),
				ContextTokens: jobKeyCtx,
				Message:       fmt.Sprintf("job %q has unknown key %q", jobID, key),
			})
		}
	}

	if hasRunsOn {
		errs = append(errs, checkRunsOn(jobID, jobsKeyToken, jobKey, runsOnKV)...)
	}
	if hasSteps {
		errs = append(errs, checkStepsType(jobID, jobsKeyToken, jobKey, stepsKV)...)
	}
	if hasUses {
		errs = append(errs, checkUsesType(jobID, jobsKeyToken, jobKey, usesKV)...)
	}

	// Strategy check
	strategyKV := job.FindKey("strategy")
	if strategyKV != nil {
		errs = append(errs, checkStrategy(jobID, strategyKV, jobKeyCtx)...)
	}

	jobLabel := fmt.Sprintf("job %q", jobID)

	// Concurrency check
	concurrencyKV := job.FindKey("concurrency")
	if concurrencyKV != nil {
		errs = append(errs, checkConcurrencyMapping(jobLabel, concurrencyKV, jobKeyCtx)...)
	}

	// Defaults check
	defaultsKV := job.FindKey("defaults")
	if defaultsKV != nil {
		errs = append(errs, checkDefaults(jobLabel, defaultsKV, jobKeyCtx)...)
	}

	// Permissions check
	permissionsKV := job.FindKey("permissions")
	if permissionsKV != nil {
		errs = append(errs, checkPermissions(jobLabel, permissionsKV, jobKeyCtx)...)
	}

	// Step validation (when steps is a valid sequence)
	if hasSteps {
		if seq, ok := stepsKV.Value.(*ast.SequenceNode); ok {
			errs = append(errs, checkStepEntries(jobID, jobsKeyToken, jobKey, stepsKV.Key.GetToken(), seq)...)
		}
	}

	return errs
}

func checkRunsOn(jobID string, jobsKeyToken *token.Token, jobKey *token.Token, kv *ast.MappingValueNode) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}

	jobKeyCtx := []*token.Token{jobsKeyToken, jobKey}
	runsOnCtx := extendContext(jobKeyCtx, kv.Key.GetToken())

	switch v := kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	case *ast.SequenceNode:
		return checkRunsOnSequence(jobID, v, runsOnCtx)
	case *ast.MappingNode:
		return checkRunsOnMapping(jobID, v, runsOnCtx)
	default:
		return []*diagnostic.Error{{
			Token:         kv.Value.GetToken(),
			ContextTokens: jobKeyCtx,
			Message:       fmt.Sprintf("job %q \"runs-on\" must be a string, sequence, or mapping, but got %s", jobID, kv.Value.Type()),
		}}
	}
}

func checkRunsOnMapping(jobID string, m *ast.MappingNode, contextTokens []*token.Token) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range m.Values {
		key := entry.Key.GetToken().Value
		if !knownRunsOnKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:         entry.Key.GetToken(),
				ContextTokens: contextTokens,
				Message:       fmt.Sprintf("job %q \"runs-on\" has unknown key %q; valid keys are \"group\" and \"labels\"", jobID, key),
			})
		}
	}
	return errs
}

func checkRunsOnSequence(jobID string, seq *ast.SequenceNode, contextTokens []*token.Token) []*diagnostic.Error {
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
				Token:         elem.GetToken(),
				ContextTokens: contextTokens,
				Message:       fmt.Sprintf("job %q \"runs-on\" sequence elements must be strings, but got %s", jobID, elem.Type()),
			})
		}
	}
	return errs
}

func checkStepsType(jobID string, jobsKeyToken *token.Token, jobKey *token.Token, kv *ast.MappingValueNode) []*diagnostic.Error {
	_, ok := kv.Value.(*ast.SequenceNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:         kv.Value.GetToken(),
			ContextTokens: []*token.Token{jobsKeyToken, jobKey},
			Message:       fmt.Sprintf("job %q \"steps\" must be a sequence, but got %s", jobID, kv.Value.Type()),
		}}
	}
	return nil
}

func checkUsesType(jobID string, jobsKeyToken *token.Token, jobKey *token.Token, kv *ast.MappingValueNode) []*diagnostic.Error {
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return nil
	default:
		return []*diagnostic.Error{{
			Token:         kv.Value.GetToken(),
			ContextTokens: []*token.Token{jobsKeyToken, jobKey},
			Message:       fmt.Sprintf("job %q \"uses\" must be a string, but got %s", jobID, kv.Value.Type()),
		}}
	}
}

func checkStrategy(jobID string, kv *ast.MappingValueNode, contextTokens []*token.Token) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}

	stratCtx := extendContext(contextTokens, kv.Key.GetToken())

	strategyMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return []*diagnostic.Error{{
			Token:         kv.Value.GetToken(),
			ContextTokens: stratCtx,
			Message:       fmt.Sprintf("job %q \"strategy\" must be a mapping, but got %s", jobID, kv.Value.Type()),
		}}
	}

	matrixKV := workflow.Mapping{MappingNode: strategyMapping}.FindKey("matrix")
	if matrixKV == nil {
		return []*diagnostic.Error{{
			Token:         kv.Key.GetToken(),
			ContextTokens: stratCtx,
			Message:       fmt.Sprintf("job %q \"strategy\" must have a \"matrix\" key", jobID),
		}}
	}
	return nil
}
