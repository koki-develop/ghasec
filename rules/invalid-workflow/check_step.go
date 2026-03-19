package invalidworkflow

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

func checkStepEntries(jobsKeyToken *token.Token, jobKey *token.Token, stepsKeyToken *token.Token, seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		stepMapping, ok := item.(*ast.MappingNode)
		if !ok {
			errs = append(errs, &diagnostic.Error{
				Token:         item.GetToken(),
				ContextTokens: []*token.Token{jobsKeyToken, jobKey, stepsKeyToken, workflow.FindSeqEntryToken(item.GetToken())},
				Message:       fmt.Sprintf("step must be a mapping, but got %s", item.Type()),
			})
			continue
		}
		seqEntry := workflow.FindSeqEntryToken(stepMapping.GetToken())
		errs = append(errs, checkStep(jobsKeyToken, jobKey, stepsKeyToken, seqEntry, workflow.Mapping{MappingNode: stepMapping})...)
	}
	return errs
}

func checkStep(jobsKeyToken *token.Token, jobKey *token.Token, stepsKeyToken *token.Token, seqEntryToken *token.Token, step workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	contextTokens := []*token.Token{jobsKeyToken, jobKey, stepsKeyToken, seqEntryToken}

	usesKV := step.FindKey("uses")
	runKV := step.FindKey("run")

	hasUses := usesKV != nil
	hasRun := runKV != nil

	if !hasUses && !hasRun {
		errs = append(errs, &diagnostic.Error{
			Token:         step.GetToken(),
			ContextTokens: contextTokens,
			Message:       "\"uses\" or \"run\" is required",
		})
	}
	if hasUses && hasRun {
		firstToken := usesKV.Key.GetToken()
		secondToken := runKV.Key.GetToken()
		if secondToken.Position.Offset < firstToken.Position.Offset {
			firstToken, secondToken = secondToken, firstToken
		}
		errs = append(errs, &diagnostic.Error{
			Token:         firstToken,
			ContextTokens: contextTokens,
			Message:       "\"uses\" and \"run\" are mutually exclusive",
			Markers:       []*token.Token{secondToken},
		})
	}

	for _, entry := range step.Values {
		key := entry.Key.GetToken().Value
		if !knownStepKeys[key] {
			errs = append(errs, &diagnostic.Error{
				Token:         entry.Key.GetToken(),
				ContextTokens: contextTokens,
				Message:       fmt.Sprintf("unknown key %q", key),
			})
		}
	}

	return errs
}
