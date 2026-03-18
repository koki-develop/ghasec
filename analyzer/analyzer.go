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
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		return nil
	}

	var requiredErrs []*diagnostic.Error
	var nonRequiredRules []rules.Rule

	for _, r := range a.rules {
		if r.Required() {
			requiredErrs = append(requiredErrs, r.Check(f)...)
		} else {
			nonRequiredRules = append(nonRequiredRules, r)
		}
	}

	if len(requiredErrs) > 0 {
		return requiredErrs
	}

	var errs []*diagnostic.Error
	for _, r := range nonRequiredRules {
		errs = append(errs, r.Check(f)...)
	}
	return errs
}
