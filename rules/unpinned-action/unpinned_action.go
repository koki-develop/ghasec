package unpinnedaction

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/git"
	"github.com/koki-develop/ghasec/rules"
)

const id = "unpinned-action"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Check(mapping *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	rules.EachStep(mapping, func(step *ast.MappingNode) {
		if err := checkStepAction(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func checkStepAction(step *ast.MappingNode) *diagnostic.Error {
	usesValue, usesToken, ok := rules.StepUsesValue(step)
	if !ok {
		return nil
	}

	if rules.IsLocalAction(usesValue) || rules.IsDockerAction(usesValue) {
		return nil
	}

	atIdx := strings.LastIndex(usesValue, "@")
	if atIdx == -1 || !git.Ref(usesValue[atIdx+1:]).IsFullSHA() {
		return &diagnostic.Error{
			Token:   usesToken,
			Message: fmt.Sprintf("action %q must be pinned to a full length commit SHA", usesValue),
		}
	}

	return nil
}
