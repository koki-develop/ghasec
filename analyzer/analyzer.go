package analyzer

import (
	"fmt"
	"slices"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/ignore"
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

	directives := collectDirectives(f)
	knownIDs := a.allRuleIDs()
	requiredIDs := a.requiredRuleIDs()

	requiredIgnoreErrs := checkRequiredIgnores(directives, requiredIDs)

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
		return append(requiredErrs, requiredIgnoreErrs...)
	}

	var lintErrs []*diagnostic.Error
	for _, r := range nonRequiredRules {
		for _, e := range r.CheckWorkflow(mapping) {
			e.RuleID = r.ID()
			lintErrs = append(lintErrs, e)
		}
	}

	filtered := filterDiagnostics(directives, lintErrs)
	unusedErrs := unusedIgnoreErrors(directives, knownIDs)
	return slices.Concat(filtered, unusedErrs, requiredIgnoreErrs)
}

func (a *Analyzer) AnalyzeAction(f *ast.File) []*diagnostic.Error {
	mapping, errs := actionTopLevelMapping(f)
	if errs != nil {
		return errs
	}

	directives := collectDirectives(f)
	knownIDs := a.allRuleIDs()
	requiredIDs := a.requiredRuleIDs()

	requiredIgnoreErrs := checkRequiredIgnores(directives, requiredIDs)

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
		return append(requiredErrs, requiredIgnoreErrs...)
	}

	var lintErrs []*diagnostic.Error
	for _, r := range nonRequiredRules {
		for _, e := range r.CheckAction(mapping) {
			e.RuleID = r.ID()
			lintErrs = append(lintErrs, e)
		}
	}

	filtered := filterDiagnostics(directives, lintErrs)
	unusedErrs := unusedIgnoreErrors(directives, knownIDs)
	return slices.Concat(filtered, unusedErrs, requiredIgnoreErrs)
}

func (a *Analyzer) allRuleIDs() map[string]bool {
	ids := make(map[string]bool)
	for _, r := range a.workflowRules {
		ids[r.ID()] = true
	}
	for _, r := range a.actionRules {
		ids[r.ID()] = true
	}
	return ids
}

func (a *Analyzer) requiredRuleIDs() map[string]bool {
	ids := make(map[string]bool)
	for _, r := range a.workflowRules {
		if r.Required() {
			ids[r.ID()] = true
		}
	}
	for _, r := range a.actionRules {
		if r.Required() {
			ids[r.ID()] = true
		}
	}
	return ids
}

func collectDirectives(f *ast.File) []*ignore.Directive {
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		return nil
	}
	tk := f.Docs[0].Body.GetToken()
	if tk == nil {
		return nil
	}
	for tk.Prev != nil {
		tk = tk.Prev
	}
	return ignore.Collect(tk)
}

// checkRequiredIgnores marks directives that explicitly target required rules
// by name and returns error diagnostics. All-rules directives (empty RuleIDs)
// silently skip required rules — they only suppress non-required diagnostics.
func checkRequiredIgnores(directives []*ignore.Directive, requiredIDs map[string]bool) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, d := range directives {
		for _, id := range d.RuleIDs {
			if requiredIDs[id] {
				d.MarkUsed(id)
				errs = append(errs, &diagnostic.Error{
					Token:   d.RuleIDToken(id),
					RuleID:  "unused-ignore",
					Message: fmt.Sprintf("%q is a required rule and cannot be ignored", id),
				})
			}
		}
	}
	return errs
}

func filterDiagnostics(directives []*ignore.Directive, errs []*diagnostic.Error) []*diagnostic.Error {
	var filtered []*diagnostic.Error
	for _, e := range errs {
		if e.Token == nil || e.Token.Position == nil {
			filtered = append(filtered, e)
			continue
		}
		suppressed := false
		for _, d := range directives {
			if d.Line != e.Token.Position.Line {
				continue
			}
			if len(d.RuleIDs) == 0 || slices.Contains(d.RuleIDs, e.RuleID) {
				d.MarkUsed(e.RuleID)
				suppressed = true
				break
			}
		}
		if !suppressed {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func unusedIgnoreErrors(directives []*ignore.Directive, knownIDs map[string]bool) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, d := range directives {
		if len(d.RuleIDs) == 0 {
			// All-rules directive: unused if nothing was suppressed
			if d.IsFullyUsed() {
				continue
			}
			errs = append(errs, &diagnostic.Error{
				Token:   d.KeywordToken(),
				RuleID:  "unused-ignore",
				Message: "unused ignore directive",
			})
			continue
		}
		// Per-rule-ID: check each individually
		for _, id := range d.RuleIDs {
			if d.IsUsed(id) {
				continue
			}
			msg := fmt.Sprintf("unused ignore directive for %q", id)
			if !knownIDs[id] {
				msg = fmt.Sprintf("unknown rule %q", id)
			}
			errs = append(errs, &diagnostic.Error{
				Token:   d.RuleIDToken(id),
				RuleID:  "unused-ignore",
				Message: msg,
			})
		}
	}
	return errs
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
