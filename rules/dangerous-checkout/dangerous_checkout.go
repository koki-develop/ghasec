package dangerouscheckout

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "dangerous-checkout"

var dangerousRefPatterns = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.head_ref",
	"github.event.pull_request.number",
	"github.event.number",
	"github.event.pull_request.merge_commit_sha",
}

// Rule implements WorkflowRule only. Action files lack trigger definitions,
// so we cannot determine whether a checkout is dangerous without cross-file
// analysis of the calling workflow's triggers.
type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Workflows triggered by pull_request_target or workflow_run run with access to repository secrets. Checking out pull request head code — either via a ref pointing to the fork head or via allow-unsafe-pr-checkout: true — lets attacker-controlled code execute with those secrets"
}

func (r *Rule) Fix() string {
	return "Remove the ref parameter from actions/checkout so it checks out the base branch code, and do not set allow-unsafe-pr-checkout to true"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	hasPRTarget := hasTrigger(mapping, "pull_request_target")
	hasWorkflowRun := hasTrigger(mapping, "workflow_run")
	if !hasPRTarget && !hasWorkflowRun {
		return nil
	}
	return rules.CollectStepErrors(mapping.EachStep, func(step workflow.StepMapping) []*diagnostic.Error {
		return checkStep(step, hasPRTarget, hasWorkflowRun)
	})
}

func hasTrigger(mapping workflow.WorkflowMapping, name string) bool {
	onKV := mapping.FindKey("on")
	if onKV == nil {
		return false
	}

	node := rules.UnwrapNode(onKV.Value)
	switch v := node.(type) {
	case *ast.StringNode:
		return v.Value == name
	case *ast.SequenceNode:
		for _, item := range v.Values {
			if s := rules.StringValue(item); s == name {
				return true
			}
		}
	case *ast.MappingNode:
		for _, entry := range v.Values {
			if entry.Key.GetToken().Value == name {
				return true
			}
		}
	}
	return false
}

func checkStep(step workflow.StepMapping, hasPRTarget, hasWorkflowRun bool) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}

	if !strings.HasPrefix(ref.String(), "actions/checkout@") {
		return nil
	}

	withMapping, ok := step.With()
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error

	// "ref" pattern detection is scoped to pull_request_target only — the
	// expressions in dangerousRefPatterns are specific to the pull_request
	// event payload, which workflow_run does not carry.
	if hasPRTarget {
		if e := checkRef(withMapping, ref); e != nil {
			errs = append(errs, e)
		}
	}

	// "allow-unsafe-pr-checkout: true" is dangerous in both pull_request_target
	// and workflow_run workflows — the official input applies to both triggers.
	if e := checkAllowUnsafePRCheckout(withMapping, ref, hasPRTarget, hasWorkflowRun); e != nil {
		errs = append(errs, e)
	}

	return errs
}

func checkRef(withMapping workflow.Mapping, ref workflow.ActionRef) *diagnostic.Error {
	refKV := withMapping.FindKey("ref")
	if refKV == nil {
		return nil
	}

	refValue := rules.StringValue(refKV.Value)
	if refValue == "" {
		return nil
	}

	for _, pattern := range dangerousRefPatterns {
		if strings.Contains(refValue, pattern) {
			return &diagnostic.Error{
				Token:         rules.UnwrapNode(refKV.Value).GetToken(),
				ExtraContexts: []*token.Token{ref.Token()},
				Message:       `"ref" must not reference pull request head in a "pull_request_target" workflow`,
			}
		}
	}

	return nil
}

func checkAllowUnsafePRCheckout(withMapping workflow.Mapping, ref workflow.ActionRef, hasPRTarget, hasWorkflowRun bool) *diagnostic.Error {
	kv := withMapping.FindKey("allow-unsafe-pr-checkout")
	if kv == nil {
		return nil
	}

	if !isTrueValue(kv.Value) {
		return nil
	}

	trigger := "pull_request_target"
	if !hasPRTarget && hasWorkflowRun {
		trigger = "workflow_run"
	}

	return &diagnostic.Error{
		Token:         rules.UnwrapNode(kv.Value).GetToken(),
		ExtraContexts: []*token.Token{ref.Token()},
		Message:       fmt.Sprintf(`"allow-unsafe-pr-checkout" must not be true in a %q workflow`, trigger),
	}
}

func isTrueValue(n ast.Node) bool {
	unwrapped := rules.UnwrapNode(n)
	switch v := unwrapped.(type) {
	case *ast.BoolNode:
		return v.Value
	case *ast.StringNode:
		return strings.EqualFold(v.Value, "true")
	}
	return false
}
