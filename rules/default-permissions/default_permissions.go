package defaultpermissions

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

const id = "default-permissions"

const message = `workflow-level "permissions" must be set to {}; grant permissions per job instead`

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Check(mapping *ast.MappingNode) []*diagnostic.Error {
	fileStart := rules.FirstToken(mapping.GetToken())

	permKV := rules.FindKey(mapping, "permissions")
	if permKV == nil {
		return []*diagnostic.Error{{
			Token:   fileStart,
			Message: message,
		}}
	}

	if isEmptyMapping(permKV.Value) {
		return nil
	}

	return []*diagnostic.Error{{
		Token:      permKV.Key.GetToken(),
		AfterToken: lastValueToken(permKV.Value),
		Message:    message,
	}}
}

func lastValueToken(node ast.Node) *token.Token {
	m, ok := node.(*ast.MappingNode)
	if !ok || len(m.Values) == 0 {
		return node.GetToken()
	}
	last := m.Values[len(m.Values)-1]
	return last.Value.GetToken()
}

func isEmptyMapping(node ast.Node) bool {
	m, ok := node.(*ast.MappingNode)
	if !ok {
		return false
	}
	return len(m.Values) == 0
}
