package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

// Hand-written validation extensions.
// These run AFTER generated validation and ADD errors — they never replace or skip
// generated validation. They cover validations that JSON Schema cannot express.

// B1: Filter conflicts — branches/branches-ignore, tags/tags-ignore, paths/paths-ignore.
func checkOnFilterConflicts(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil
	}
	onMapping, ok := rules.UnwrapNode(kv.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}
	var errs []*diagnostic.Error
	for _, entry := range onMapping.Values {
		eventMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: eventMapping}
		errs = append(errs, checkFilterConflict(m, "branches", "branches-ignore")...)
		errs = append(errs, checkFilterConflict(m, "tags", "tags-ignore")...)
		errs = append(errs, checkFilterConflict(m, "paths", "paths-ignore")...)
	}
	return errs
}

func checkFilterConflict(m workflow.Mapping, a, b string) []*diagnostic.Error {
	aKV := m.FindKey(a)
	bKV := m.FindKey(b)
	if aKV == nil || bKV == nil {
		return nil
	}
	firstToken := aKV.Key.GetToken()
	secondToken := bKV.Key.GetToken()
	if secondToken.Position.Offset < firstToken.Position.Offset {
		firstToken, secondToken = secondToken, firstToken
	}
	return []*diagnostic.Error{{
		Token:   firstToken,
		Message: fmt.Sprintf("%q and %q are mutually exclusive", a, b),
		Markers: []*token.Token{secondToken},
	}}
}

// checkJobExtensions runs hand-written checks on each job entry.
func checkJobExtensions(jobs *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, jobEntry := range jobs.Values {
		jobMapping, ok := rules.UnwrapNode(jobEntry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: jobMapping}

		// B2: Job-level mutual exclusion
		errs = append(errs, checkJobMutualExclusion(jobEntry.Key.GetToken(), m)...)

		// Step validation
		if stepsKV := m.FindKey("steps"); stepsKV != nil {
			if seq, ok := rules.UnwrapNode(stepsKV.Value).(*ast.SequenceNode); ok {
				errs = append(errs, checkStepExtensions(seq)...)
			}
		}
	}
	return errs
}

// B2: Job mutual exclusion — runs-on/uses, uses/steps.
func checkJobMutualExclusion(jobKey *token.Token, job workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	runsOnKV := job.FindKey("runs-on")
	usesKV := job.FindKey("uses")
	stepsKV := job.FindKey("steps")

	if runsOnKV != nil && usesKV != nil {
		firstToken := runsOnKV.Key.GetToken()
		secondToken := usesKV.Key.GetToken()
		if secondToken.Position.Offset < firstToken.Position.Offset {
			firstToken, secondToken = secondToken, firstToken
		}
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: "\"runs-on\" and \"uses\" are mutually exclusive",
			Markers: []*token.Token{firstToken, secondToken},
		})
	}
	if usesKV != nil && stepsKV != nil {
		firstToken := usesKV.Key.GetToken()
		secondToken := stepsKV.Key.GetToken()
		if secondToken.Position.Offset < firstToken.Position.Offset {
			firstToken, secondToken = secondToken, firstToken
		}
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: "\"uses\" and \"steps\" are mutually exclusive",
			Markers: []*token.Token{firstToken, secondToken},
		})
	}
	return errs
}

// checkStepExtensions runs hand-written checks on each step.
func checkStepExtensions(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		stepMapping, ok := rules.UnwrapNode(item).(*ast.MappingNode)
		if !ok {
			continue
		}
		step := workflow.Mapping{MappingNode: stepMapping}

		// B3: Step mutual exclusion — uses/run
		usesKV := step.FindKey("uses")
		runKV := step.FindKey("run")
		if usesKV != nil && runKV != nil {
			firstToken := usesKV.Key.GetToken()
			secondToken := runKV.Key.GetToken()
			if secondToken.Position.Offset < firstToken.Position.Offset {
				firstToken, secondToken = secondToken, firstToken
			}
			errs = append(errs, &diagnostic.Error{
				Token:   firstToken,
				Message: "\"uses\" and \"run\" are mutually exclusive",
				Markers: []*token.Token{secondToken},
			})
		}

		// C1: Remote action ref format
		if usesKV != nil {
			stepW := workflow.StepMapping{Mapping: step}
			ref, ok := stepW.Uses()
			if ok && !ref.IsLocal() && !ref.IsDocker() && ref.Ref() == "" {
				errs = append(errs, &diagnostic.Error{
					Token:   ref.Token(),
					Message: fmt.Sprintf("%q must have a ref (e.g. %s@<ref>)", ref.String(), ref.String()),
				})
			}
		}
	}
	return errs
}
