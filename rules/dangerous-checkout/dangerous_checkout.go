package dangerouscheckout

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "dangerous-checkout"

var dangerousPatterns = []string{
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

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	if !hasPullRequestTarget(mapping) {
		return nil
	}

	var errs []*diagnostic.Error
	mapping.EachStep(func(step workflow.StepMapping) {
		if err := checkStep(step); err != nil {
			errs = append(errs, err)
		}
	})
	return errs
}

func hasPullRequestTarget(mapping workflow.WorkflowMapping) bool {
	onKV := mapping.FindKey("on")
	if onKV == nil {
		return false
	}

	node := rules.UnwrapNode(onKV.Value)
	switch v := node.(type) {
	case *ast.StringNode:
		return v.Value == "pull_request_target"
	case *ast.SequenceNode:
		for _, item := range v.Values {
			if s := rules.StringValue(item); s == "pull_request_target" {
				return true
			}
		}
	case *ast.MappingNode:
		for _, entry := range v.Values {
			if entry.Key.GetToken().Value == "pull_request_target" {
				return true
			}
		}
	}
	return false
}

func checkStep(step workflow.StepMapping) *diagnostic.Error {
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

	refKV := withMapping.FindKey("ref")
	if refKV == nil {
		return nil
	}

	refValue := rules.StringValue(refKV.Value)
	if refValue == "" {
		return nil
	}

	for _, pattern := range dangerousPatterns {
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
