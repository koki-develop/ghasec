package analyzer

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
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
	mapping, errs := topLevelMapping(f)
	if errs != nil {
		return errs
	}

	var requiredErrs []*diagnostic.Error
	var nonRequiredRules []rules.Rule

	for _, r := range a.rules {
		if r.Required() {
			for _, e := range r.Check(mapping) {
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
		for _, e := range r.Check(mapping) {
			e.RuleID = r.ID()
			lintErrs = append(lintErrs, e)
		}
	}
	return lintErrs
}

func topLevelMapping(f *ast.File) (*ast.MappingNode, []*diagnostic.Error) {
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		tk := &token.Token{
			Position: &token.Position{
				Line:   1,
				Column: 1,
				Offset: 1,
			},
			Value: " ",
		}
		return nil, []*diagnostic.Error{{Token: tk, Message: "workflow must be a YAML mapping"}}
	}

	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return nil, []*diagnostic.Error{{
			Token:   f.Docs[0].Body.GetToken(),
			Message: "workflow must be a YAML mapping",
		}}
	}
	return m, nil
}
