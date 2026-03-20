package invalidworkflow

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules/step"
)

func checkStepEntries(seq *ast.SequenceNode) []*diagnostic.Error {
	return step.CheckEntries(seq, step.CheckOptions{KnownKeys: knownStepKeys})
}
