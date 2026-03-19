package checkoutpersistcredentials

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "checkout-persist-credentials"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Check(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		if err := checkStep(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func checkStep(step workflow.StepMapping) *diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if !isCheckoutAction(ref.String()) {
		return nil
	}

	errToken, found := findPersistCredentialsError(step)
	if found {
		return nil
	}

	usesToken := ref.Token()
	if errToken == nil {
		errToken = usesToken
	}

	ctx := []*token.Token{step.JobsKeyToken(), step.JobKeyToken(), step.StepsKeyToken(), step.SeqEntryToken()}
	if errToken != usesToken {
		ctx = append(ctx, usesToken)
		if withKV := step.FindKey("with"); withKV != nil {
			ctx = append(ctx, withKV.Key.GetToken())
		}
	}

	return &diagnostic.Error{
		Token:         errToken,
		ContextTokens: ctx,
		Message:       `"persist-credentials: false" must be set in "with"`,
	}
}

func isCheckoutAction(uses string) bool {
	return uses == "actions/checkout" || strings.HasPrefix(uses, "actions/checkout@")
}

// findPersistCredentialsError checks if persist-credentials is set to false.
// Returns (nil, true) if correctly set to false.
// Returns (token, false) if persist-credentials exists but is not false (token points to the bad value).
// Returns (nil, false) if persist-credentials or with is missing.
func findPersistCredentialsError(step workflow.StepMapping) (*token.Token, bool) {
	withMapping, ok := step.With()
	if !ok {
		return nil, false
	}

	pcKV := withMapping.FindKey("persist-credentials")
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
