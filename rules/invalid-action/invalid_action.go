package invalidaction

import (
	"fmt"
	"strings"

	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-action"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	// Generated schema validation (covers: top-level unknown/required keys,
	// author type check, branding unknown keys + color/icon type/enum checks).
	fileStart := mapping.FirstToken()
	genErrs := rules.Dedup(validateAction(mapping))
	// Fix error tokens BEFORE sorting
	for i := range genErrs {
		// Top-level required errors should point to file start
		if genErrs[i].Kind == rules.KindRequiredKey && genErrs[i].Path == "" {
			genErrs[i].Token = fileStart
		}
	}
	for _, ve := range rules.SortRequiredFirst(genErrs) {
		if isHandWrittenPath(ve.Path) {
			continue
		}
		errs = append(errs, toDiagnostic(ve))
	}

	// Hand-written checks NOT covered by generated validator:

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

	return errs
}

// toDiagnostic converts a generated ValidationError to a diagnostic.Error,
// producing messages that match the hand-written format.
func toDiagnostic(ve rules.ValidationError) *diagnostic.Error {
	var msg string
	switch ve.Kind {
	case rules.KindUnknownKey:
		if ve.Parent != "" && ve.Context != "" {
			msg = fmt.Sprintf("%q has unknown %s %q", ve.Parent, ve.Context, ve.Key)
		} else if ve.Parent != "" {
			msg = fmt.Sprintf("%q has unknown key %q", ve.Parent, ve.Key)
		} else {
			msg = fmt.Sprintf("unknown key %q", ve.Key)
		}
	case rules.KindRequiredKey:
		msg = fmt.Sprintf("%q is required", ve.Key)
	case rules.KindTypeMismatch:
		msg = fmt.Sprintf("%q must be a %s, but got %s", ve.Key, strings.Join(ve.Allowed, " or "), ve.Got)
	case rules.KindInvalidEnum:
		if ve.Parent != "" && ve.Context != "" {
			msg = fmt.Sprintf("%q has unknown %s %q", ve.Parent, ve.Context, ve.Got)
		} else {
			msg = fmt.Sprintf("%q has unknown value %q", ve.Key, ve.Got)
		}
	default:
		msg = fmt.Sprintf("validation error on %q: %s", ve.Key, ve.Got)
	}
	return &diagnostic.Error{Token: ve.Token, Message: msg}
}

// isHandWrittenPath returns true if errors at this path are handled by
// hand-written checks (runs, inputs, outputs).
func isHandWrittenPath(path string) bool {
	// runs: deep validation with better messages, uses .Type() for casing
	if path == "runs" || strings.HasPrefix(path, "runs.") {
		return true
	}
	// inputs: domain-specific messages like `input "name" has unknown key`
	if path == "inputs" || strings.HasPrefix(path, "inputs.") {
		return true
	}
	// outputs: depends on using value (composite outputs require "value" key)
	if path == "outputs" || strings.HasPrefix(path, "outputs.") {
		return true
	}
	return false
}
