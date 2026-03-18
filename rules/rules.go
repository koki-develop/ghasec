package rules

import (
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
)

type Rule interface {
	ID() string
	Required() bool
	Online() bool
	Check(mapping *ast.MappingNode) []*diagnostic.Error
}

func TopLevelMapping(doc *ast.DocumentNode) *ast.MappingNode {
	if doc.Body == nil {
		return nil
	}
	m, ok := doc.Body.(*ast.MappingNode)
	if !ok {
		return nil
	}
	return m
}

func FindKey(mapping *ast.MappingNode, key string) *ast.MappingValueNode {
	for _, v := range mapping.Values {
		if v.Key.GetToken().Value == key {
			return v
		}
	}
	return nil
}

func EachStep(mapping *ast.MappingNode, fn func(step *ast.MappingNode)) {
	jobsKV := FindKey(mapping, "jobs")
	if jobsKV == nil {
		return
	}
	jobsMapping, ok := jobsKV.Value.(*ast.MappingNode)
	if !ok {
		return
	}
	for _, jobEntry := range jobsMapping.Values {
		jobMapping, ok := jobEntry.Value.(*ast.MappingNode)
		if !ok {
			continue
		}
		stepsKV := FindKey(jobMapping, "steps")
		if stepsKV == nil {
			continue
		}
		stepsSeq, ok := stepsKV.Value.(*ast.SequenceNode)
		if !ok {
			continue
		}
		for _, stepNode := range stepsSeq.Values {
			stepMapping, ok := stepNode.(*ast.MappingNode)
			if !ok {
				continue
			}
			fn(stepMapping)
		}
	}
}

func StepUsesValue(step *ast.MappingNode) (string, *token.Token, bool) {
	usesKV := FindKey(step, "uses")
	if usesKV == nil {
		return "", nil, false
	}
	switch v := usesKV.Value.(type) {
	case *ast.StringNode:
		return v.Value, v.GetToken(), true
	case *ast.LiteralNode:
		return v.Value.Value, v.GetToken(), true
	}
	return "", nil, false
}

func IsLocalAction(uses string) bool {
	return strings.HasPrefix(uses, "./")
}

func IsDockerAction(uses string) bool {
	return strings.HasPrefix(uses, "docker://")
}

func FirstToken(tk *token.Token) *token.Token {
	for tk.Prev != nil {
		tk = tk.Prev
	}
	cp := *tk
	cp.Value = string(tk.Value[0])
	return &cp
}
