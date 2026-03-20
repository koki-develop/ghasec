package analyzer

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

type Analyzer struct {
	workflowRules []rules.WorkflowRule
	actionRules   []rules.ActionRule
}

func New(rr ...rules.Rule) *Analyzer {
	a := &Analyzer{}
	for _, r := range rr {
		wr, isWorkflow := r.(rules.WorkflowRule)
		ar, isAction := r.(rules.ActionRule)
		if !isWorkflow && !isAction {
			panic("rule must implement WorkflowRule or ActionRule")
		}
		if isWorkflow {
			a.workflowRules = append(a.workflowRules, wr)
		}
		if isAction {
			a.actionRules = append(a.actionRules, ar)
		}
	}
	return a
}

func (a *Analyzer) AnalyzeWorkflow(f *ast.File) []*diagnostic.Error {
	mapping, errs := workflowTopLevelMapping(f)
	if errs != nil {
		return errs
	}

	var requiredErrs []*diagnostic.Error
	var nonRequiredRules []rules.WorkflowRule

	for _, r := range a.workflowRules {
		if r.Required() {
			for _, e := range r.CheckWorkflow(mapping) {
				e.RuleID = r.ID()
				requiredErrs = append(requiredErrs, e)
			}
		} else {
			nonRequiredRules = append(nonRequiredRules, r)
		}
	}

	if len(requiredErrs) > 0 {
		return requiredErrs
	}

	var lintErrs []*diagnostic.Error
	for _, r := range nonRequiredRules {
		for _, e := range r.CheckWorkflow(mapping) {
			e.RuleID = r.ID()
			lintErrs = append(lintErrs, e)
		}
	}
	return lintErrs
}

func (a *Analyzer) AnalyzeAction(f *ast.File) []*diagnostic.Error {
	mapping, errs := actionTopLevelMapping(f)
	if errs != nil {
		return errs
	}

	var requiredErrs []*diagnostic.Error
	var nonRequiredRules []rules.ActionRule

	for _, r := range a.actionRules {
		if r.Required() {
			for _, e := range r.CheckAction(mapping) {
				e.RuleID = r.ID()
				requiredErrs = append(requiredErrs, e)
			}
		} else {
			nonRequiredRules = append(nonRequiredRules, r)
		}
	}

	if len(requiredErrs) > 0 {
		return requiredErrs
	}

	var lintErrs []*diagnostic.Error
	for _, r := range nonRequiredRules {
		for _, e := range r.CheckAction(mapping) {
			e.RuleID = r.ID()
			lintErrs = append(lintErrs, e)
		}
	}
	return lintErrs
}

func emptyDocToken() *token.Token {
	return &token.Token{
		Position: &token.Position{
			Line:   1,
			Column: 1,
			Offset: 1,
		},
		Value: " ",
	}
}

func workflowTopLevelMapping(f *ast.File) (workflow.WorkflowMapping, []*diagnostic.Error) {
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		return workflow.WorkflowMapping{}, []*diagnostic.Error{{Token: emptyDocToken(), Message: "workflow must be a YAML mapping"}}
	}

	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return workflow.WorkflowMapping{}, []*diagnostic.Error{{
			Token:   f.Docs[0].Body.GetToken(),
			Message: "workflow must be a YAML mapping",
		}}
	}
	return workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}, nil
}

func actionTopLevelMapping(f *ast.File) (workflow.ActionMapping, []*diagnostic.Error) {
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		return workflow.ActionMapping{}, []*diagnostic.Error{{Token: emptyDocToken(), Message: "action must be a YAML mapping"}}
	}

	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return workflow.ActionMapping{}, []*diagnostic.Error{{
			Token:   f.Docs[0].Body.GetToken(),
			Message: "action must be a YAML mapping",
		}}
	}
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}, nil
}
