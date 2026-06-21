package dangerouscheckout

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "dangerous-checkout"

// dangerousPRTargetRefPatterns lists context expressions on `with.ref` that
// resolve to the pull request head in a pull_request_target workflow.
var dangerousPRTargetRefPatterns = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.head_ref",
	"github.event.pull_request.number",
	"github.event.number",
	"github.event.pull_request.merge_commit_sha",
}

// dangerousWorkflowRunRefRegex lists context expressions on `with.ref` that
// resolve to the pull request head in a workflow_run workflow. Regex is used
// to precisely match `pull_requests[N].head.{sha,ref}` and avoid matching the
// safe `pull_requests[N].base.*` paths.
var dangerousWorkflowRunRefRegex = []*regexp.Regexp{
	regexp.MustCompile(`github\.event\.workflow_run\.head_sha\b`),
	regexp.MustCompile(`github\.event\.workflow_run\.head_commit\.id\b`),
	regexp.MustCompile(`github\.event\.workflow_run\.pull_requests\[[^\]]+\]\.head\.(sha|ref)\b`),
	regexp.MustCompile(`github\.event\.workflow_run\.pull_requests\[[^\]]+\]\.number\b`),
}

// dangerousPRTargetRepositoryPatterns lists context expressions on
// `with.repository` that resolve to the fork pull request repository in a
// pull_request_target workflow.
var dangerousPRTargetRepositoryPatterns = []string{
	"github.event.pull_request.head.repo.full_name",
	"github.event.pull_request.head.repo.name",
	"github.event.pull_request.head.repo.id",
}

// dangerousWorkflowRunRepositoryRegex lists context expressions on
// `with.repository` that resolve to the fork pull request repository in a
// workflow_run workflow.
var dangerousWorkflowRunRepositoryRegex = []*regexp.Regexp{
	regexp.MustCompile(`github\.event\.workflow_run\.head_repository\.(full_name|name|id)\b`),
	regexp.MustCompile(`github\.event\.workflow_run\.pull_requests\[[^\]]+\]\.head\.repo\.(full_name|name|id)\b`),
}

// Rule implements WorkflowRule only. Action files lack trigger definitions,
// so we cannot determine whether a checkout is dangerous without cross-file
// analysis of the calling workflow's triggers.
type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Workflows triggered by pull_request_target or workflow_run run with access to repository secrets. Checking out pull request head code — via a ref pointing to the fork head, a repository input pointing to the fork, or allow-unsafe-pr-checkout: true — lets attacker-controlled code execute with those secrets"
}

func (r *Rule) Fix() string {
	return "Remove ref and repository inputs that point to the fork pull request head, and do not set allow-unsafe-pr-checkout to true"
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

	if hasPRTarget {
		if e := checkRefPRTarget(withMapping, ref); e != nil {
			errs = append(errs, e)
		}
		if e := checkRepository(withMapping, ref, "pull_request_target", dangerousPRTargetRepositoryPatterns, nil); e != nil {
			errs = append(errs, e)
		}
	}

	if hasWorkflowRun {
		if e := checkRefWorkflowRun(withMapping, ref); e != nil {
			errs = append(errs, e)
		}
		if e := checkRepository(withMapping, ref, "workflow_run", nil, dangerousWorkflowRunRepositoryRegex); e != nil {
			errs = append(errs, e)
		}
	}

	if e := checkAllowUnsafePRCheckout(withMapping, ref, hasPRTarget, hasWorkflowRun); e != nil {
		errs = append(errs, e)
	}

	return errs
}

func checkRefPRTarget(withMapping workflow.Mapping, ref workflow.ActionRef) *diagnostic.Error {
	refKV := withMapping.FindKey("ref")
	if refKV == nil {
		return nil
	}

	refValue := rules.StringValue(refKV.Value)
	if refValue == "" {
		return nil
	}

	for _, pattern := range dangerousPRTargetRefPatterns {
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

func checkRefWorkflowRun(withMapping workflow.Mapping, ref workflow.ActionRef) *diagnostic.Error {
	refKV := withMapping.FindKey("ref")
	if refKV == nil {
		return nil
	}

	refValue := rules.StringValue(refKV.Value)
	if refValue == "" {
		return nil
	}

	for _, re := range dangerousWorkflowRunRefRegex {
		if re.MatchString(refValue) {
			return &diagnostic.Error{
				Token:         rules.UnwrapNode(refKV.Value).GetToken(),
				ExtraContexts: []*token.Token{ref.Token()},
				Message:       `"ref" must not reference pull request head in a "workflow_run" workflow`,
			}
		}
	}

	return nil
}

// checkRepository inspects `with.repository`. Either substringPatterns or
// regexPatterns is consulted (the other is nil) depending on the trigger.
func checkRepository(withMapping workflow.Mapping, ref workflow.ActionRef, trigger string, substringPatterns []string, regexPatterns []*regexp.Regexp) *diagnostic.Error {
	repoKV := withMapping.FindKey("repository")
	if repoKV == nil {
		return nil
	}

	value := rules.StringValue(repoKV.Value)
	if value == "" {
		return nil
	}

	matched := false
	for _, pattern := range substringPatterns {
		if strings.Contains(value, pattern) {
			matched = true
			break
		}
	}
	if !matched {
		for _, re := range regexPatterns {
			if re.MatchString(value) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return nil
	}

	return &diagnostic.Error{
		Token:         rules.UnwrapNode(repoKV.Value).GetToken(),
		ExtraContexts: []*token.Token{ref.Token()},
		Message:       fmt.Sprintf(`"repository" must not reference fork pull request repository in a %q workflow`, trigger),
	}
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
