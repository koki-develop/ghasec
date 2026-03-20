package invalidaction

import (
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-action"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	errs = append(errs, checkTopLevelKeys(mapping.Mapping)...)

	using := ""
	if runsKV := mapping.FindKey("runs"); runsKV != nil {
		var runsErrs []*diagnostic.Error
		using, runsErrs = checkRuns(runsKV)
		errs = append(errs, runsErrs...)
	}

	if inputsKV := mapping.FindKey("inputs"); inputsKV != nil {
		errs = append(errs, checkInputs(inputsKV)...)
	}

	if outputsKV := mapping.FindKey("outputs"); outputsKV != nil {
		errs = append(errs, checkOutputs(outputsKV, using)...)
	}

	if brandingKV := mapping.FindKey("branding"); brandingKV != nil {
		errs = append(errs, checkBranding(brandingKV)...)
	}

	return errs
}
