package parser

import (
	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
)

// Parse reads the file at path and parses it as YAML using goccy/go-yaml.
// Returns the parsed AST.
func Parse(path string) (*ast.File, error) {
	return yamlparser.ParseFile(path, 0)
}
