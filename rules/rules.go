package rules

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
)

type Rule interface {
	ID() string
	Required() bool
	Online() bool
	Check(file *ast.File) []*diagnostic.Error
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
