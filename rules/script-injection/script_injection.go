package scriptinjection

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "script-injection"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		errs = append(errs, checkStep(step)...)
	})
	return errs
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		errs = append(errs, checkStep(step)...)
	})
	return errs
}

func checkStep(step workflow.StepMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	errs = append(errs, checkRun(step)...)
	errs = append(errs, checkGitHubScript(step)...)
	return errs
}

func checkRun(step workflow.StepMapping) []*diagnostic.Error {
	runKV := step.FindKey("run")
	if runKV == nil {
		return nil
	}
	return checkExpressions(runKV.Value, "run")
}

func checkGitHubScript(step workflow.StepMapping) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}
	owner, repo := ref.OwnerRepo()
	if !strings.EqualFold(owner, "actions") || !strings.EqualFold(repo, "github-script") {
		return nil
	}
	withMapping, ok := step.With()
	if !ok {
		return nil
	}
	scriptKV := withMapping.FindKey("script")
	if scriptKV == nil {
		return nil
	}
	return checkExpressions(scriptKV.Value, "script")
}

func checkExpressions(node ast.Node, key string) []*diagnostic.Error {
	tokens := rules.ExpressionSpanTokens(node)
	if len(tokens) == 0 {
		return nil
	}
	errs := make([]*diagnostic.Error, 0, len(tokens))
	for _, tok := range tokens {
		errs = append(errs, &diagnostic.Error{
			Token:   tok,
			Message: fmt.Sprintf("%q must not contain expressions; use environment variables instead", key),
		})
	}
	return errs
}
