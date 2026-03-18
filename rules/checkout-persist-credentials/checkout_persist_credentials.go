package checkoutpersistcredentials

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

const id = "checkout-persist-credentials"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Check(mapping *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	rules.EachStep(mapping, func(step *ast.MappingNode) {
		if err := checkStep(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func checkStep(step *ast.MappingNode) *diagnostic.Error {
	usesValue, usesToken, ok := rules.StepUsesValue(step)
	if !ok {
		return nil
	}

	if !isCheckoutAction(usesValue) {
		return nil
	}

	errToken, found := findPersistCredentialsError(step)
	if found {
		return nil
	}

	if errToken == nil {
		errToken = usesToken
	}

	e := &diagnostic.Error{
		Token:   errToken,
		Message: `actions/checkout must be configured with "persist-credentials: false"`,
	}
	if errToken != usesToken {
		e.BeforeToken = usesToken
	}
	return e
}

func isCheckoutAction(uses string) bool {
	return uses == "actions/checkout" || strings.HasPrefix(uses, "actions/checkout@")
}

// findPersistCredentialsError checks if persist-credentials is set to false.
// Returns (nil, true) if correctly set to false.
// Returns (token, false) if persist-credentials exists but is not false (token points to the bad value).
// Returns (nil, false) if persist-credentials or with is missing.
func findPersistCredentialsError(step *ast.MappingNode) (*token.Token, bool) {
	withKV := rules.FindKey(step, "with")
	if withKV == nil {
		return nil, false
	}

	withMapping, ok := withKV.Value.(*ast.MappingNode)
	if !ok {
		return nil, false
	}

	pcKV := rules.FindKey(withMapping, "persist-credentials")
	if pcKV == nil {
		return nil, false
	}

	switch v := pcKV.Value.(type) {
	case *ast.BoolNode:
		if !v.Value {
			return nil, true
		}
	case *ast.StringNode:
		if strings.EqualFold(v.Value, "false") {
			return nil, true
		}
	}

	return pcKV.Value.GetToken(), false
}
