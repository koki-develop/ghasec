package defaultpermissions

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "default-permissions"

const (
	messageMissing  = `"permissions: {}" must be set`
	messageNonEmpty = `"permissions" must be {}; grant permissions per job instead`
)

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "GitHub Actions grants broad default permissions to GITHUB_TOKEN. Without explicit restriction, every job inherits these broad defaults, increasing the blast radius if a step is compromised"
}

func (r *Rule) Fix() string {
	return "Set top-level permissions: {} and grant specific permissions per job"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	fileStart := mapping.FirstToken()

	permKV := mapping.FindKey("permissions")
	if permKV == nil {
		return []*diagnostic.Error{{
			Token:   fileStart,
			Message: messageMissing,
		}}
	}

	if isEmptyMapping(permKV.Value) {
		return nil
	}

	return []*diagnostic.Error{{
		Token:         permKV.Key.GetToken(),
		ExtraContexts: valueTokens(permKV.Value),
		Message:       messageNonEmpty,
	}}
}

func valueTokens(node ast.Node) []*token.Token {
	m, ok := rules.UnwrapNode(node).(*ast.MappingNode)
	if !ok || len(m.Values) == 0 {
		return []*token.Token{rules.UnwrapNode(node).GetToken()}
	}
	tokens := make([]*token.Token, len(m.Values))
	for i, v := range m.Values {
		tokens[i] = v.Value.GetToken()
	}
	return tokens
}

func isEmptyMapping(node ast.Node) bool {
	m, ok := rules.UnwrapNode(node).(*ast.MappingNode)
	if !ok {
		return false
	}
	return len(m.Values) == 0
}
