package invalidworkflow

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
)

// knownTopLevelKeys lists all documented top-level keys in a GitHub Actions workflow file.
var knownTopLevelKeys = map[string]bool{
	"name":        true,
	"run-name":    true,
	"on":          true,
	"permissions": true,
	"env":         true,
	"defaults":    true,
	"concurrency": true,
	"jobs":        true,
}

// knownOnEvents lists all documented GitHub Actions trigger events.
var knownOnEvents = map[string]bool{
	"branch_protection_rule":      true,
	"check_run":                   true,
	"check_suite":                 true,
	"create":                      true,
	"delete":                      true,
	"deployment":                  true,
	"deployment_status":           true,
	"discussion":                  true,
	"discussion_comment":          true,
	"fork":                        true,
	"gollum":                      true,
	"issue_comment":               true,
	"issues":                      true,
	"label":                       true,
	"merge_group":                 true,
	"milestone":                   true,
	"page_build":                  true,
	"project":                     true,
	"project_card":                true,
	"project_column":              true,
	"public":                      true,
	"pull_request":                true,
	"pull_request_review":         true,
	"pull_request_review_comment": true,
	"pull_request_target":         true,
	"push":                        true,
	"registry_package":            true,
	"release":                     true,
	"repository_dispatch":         true,
	"schedule":                    true,
	"status":                      true,
	"watch":                       true,
	"workflow_call":               true,
	"workflow_dispatch":           true,
	"workflow_run":                true,
}

// filterConflicts defines pairs of mutually exclusive filter keys.
var filterConflicts = [][2]string{
	{"branches", "branches-ignore"},
	{"tags", "tags-ignore"},
	{"paths", "paths-ignore"},
}

// knownNormalJobKeys lists all documented keys for a normal (non-reusable) job.
var knownNormalJobKeys = map[string]bool{
	"name":              true,
	"permissions":       true,
	"needs":             true,
	"if":                true,
	"runs-on":           true,
	"environment":       true,
	"concurrency":       true,
	"outputs":           true,
	"env":               true,
	"defaults":          true,
	"steps":             true,
	"timeout-minutes":   true,
	"strategy":          true,
	"continue-on-error": true,
	"container":         true,
	"services":          true,
	"snapshot":          true,
}

// knownReusableJobKeys lists all documented keys for a reusable workflow job.
var knownReusableJobKeys = map[string]bool{
	"name":        true,
	"permissions": true,
	"needs":       true,
	"if":          true,
	"uses":        true,
	"with":        true,
	"secrets":     true,
	"concurrency": true,
	"outputs":     true,
	"strategy":    true,
}

// allJobKeys is the union of normalJobKeys and reusableJobKeys.
var allJobKeys = func() map[string]bool {
	m := make(map[string]bool)
	for k := range knownNormalJobKeys {
		m[k] = true
	}
	for k := range knownReusableJobKeys {
		m[k] = true
	}
	return m
}()

// knownStepKeys lists all documented keys for a step.
var knownStepKeys = map[string]bool{
	"id":                true,
	"if":                true,
	"name":              true,
	"uses":              true,
	"run":               true,
	"working-directory": true,
	"shell":             true,
	"with":              true,
	"env":               true,
	"continue-on-error": true,
	"timeout-minutes":   true,
}

// knownPermissionScopes lists all documented permission scopes.
var knownPermissionScopes = map[string]bool{
	"actions":             true,
	"attestations":        true,
	"checks":              true,
	"contents":            true,
	"deployments":         true,
	"discussions":         true,
	"id-token":            true,
	"issues":              true,
	"packages":            true,
	"pages":               true,
	"pull-requests":       true,
	"repository-projects": true,
	"artifact-metadata":   true,
	"security-events":     true,
	"statuses":            true,
	"models":              true,
}

// knownPermissionLevels lists valid permission levels.
var knownPermissionLevels = map[string]bool{
	"read":  true,
	"write": true,
	"none":  true,
}

// modelsPermissionLevels lists valid permission levels for the "models" scope.
var modelsPermissionLevels = map[string]bool{
	"read": true,
	"none": true,
}

// knownPermissionStrings lists valid top-level permission string values.
var knownPermissionStrings = map[string]bool{
	"read-all":  true,
	"write-all": true,
}

// knownWorkflowDispatchKeys lists known keys under workflow_dispatch.
var knownWorkflowDispatchKeys = map[string]bool{
	"inputs": true,
}

// knownWorkflowDispatchInputKeys lists known keys for a workflow_dispatch input entry.
var knownWorkflowDispatchInputKeys = map[string]bool{
	"description":        true,
	"deprecationMessage": true,
	"required":           true,
	"default":            true,
	"type":               true,
	"options":            true,
}

// knownConcurrencyKeys lists known keys under concurrency mapping.
var knownConcurrencyKeys = map[string]bool{
	"group":              true,
	"cancel-in-progress": true,
}

// knownRunsOnKeys lists known keys for the runs-on mapping form.
var knownRunsOnKeys = map[string]bool{
	"group":  true,
	"labels": true,
}

// knownDefaultsRunKeys lists known keys under defaults.run.
var knownDefaultsRunKeys = map[string]bool{
	"shell":             true,
	"working-directory": true,
}

// extendContext returns a new context slice with additional tokens appended,
// without modifying the original slice.
func extendContext(base []*token.Token, extra ...*token.Token) []*token.Token {
	out := make([]*token.Token, len(base), len(base)+len(extra))
	copy(out, base)
	return append(out, extra...)
}

// isExpression reports whether the node's string value contains a ${{ expression.
func isExpression(node ast.Node) bool {
	v := stringValue(node)
	return strings.Contains(v, "${{")
}

// stringValue extracts the string value from a string or literal node.
func stringValue(node ast.Node) string {
	switch n := node.(type) {
	case *ast.StringNode:
		return n.Value
	case *ast.LiteralNode:
		return n.Value.Value
	default:
		return ""
	}
}
