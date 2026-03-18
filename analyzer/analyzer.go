package analyzer

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

type Analyzer struct {
	rules []rules.Rule
}

func New(rr ...rules.Rule) *Analyzer {
	return &Analyzer{rules: rr}
}

func (a *Analyzer) Analyze(f *ast.File) []*diagnostic.Error {
	var requiredErrs []*diagnostic.Error
	var nonRequiredRules []rules.Rule

	for _, r := range a.rules {
		if r.Required() {
			for _, e := range r.Check(f) {
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

	var errs []*diagnostic.Error
	for _, r := range nonRequiredRules {
		for _, e := range r.Check(f) {
			e.RuleID = r.ID()
			errs = append(errs, e)
		}
	}
	return errs
}
