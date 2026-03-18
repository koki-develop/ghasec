package unpinnedaction

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
)

const id = "unpinned-action"

var fullSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }

func (r *Rule) Check(f *ast.File) []*diagnostic.Error {
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		return nil
	}

	mapping := rules.TopLevelMapping(f.Docs[0])
	if mapping == nil {
		return nil
	}

	jobsKV := rules.FindKey(mapping, "jobs")
	if jobsKV == nil {
		return nil
	}

	jobsMapping, ok := jobsKV.Value.(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	for _, jobEntry := range jobsMapping.Values {
		jobMapping, ok := jobEntry.Value.(*ast.MappingNode)
		if !ok {
			continue
		}

		stepsKV := rules.FindKey(jobMapping, "steps")
		if stepsKV == nil {
			continue
		}

		seq, ok := stepsKV.Value.(*ast.SequenceNode)
		if !ok {
			continue
		}

		for _, step := range seq.Values {
			stepMapping, ok := step.(*ast.MappingNode)
			if !ok {
				continue
			}
			errs = append(errs, checkStepAction(stepMapping)...)
		}
	}
	return errs
}

func checkStepAction(step *ast.MappingNode) []*diagnostic.Error {
	usesKV := rules.FindKey(step, "uses")
	if usesKV == nil {
		return nil
	}

	var usesValue string
	switch v := usesKV.Value.(type) {
	case *ast.StringNode:
		usesValue = v.Value
	case *ast.LiteralNode:
		usesValue = v.Value.Value
	default:
		return nil
	}

	if strings.HasPrefix(usesValue, "./") || strings.HasPrefix(usesValue, "docker://") {
		return nil
	}

	atIdx := strings.LastIndex(usesValue, "@")
	if atIdx == -1 || !fullSHAPattern.MatchString(usesValue[atIdx+1:]) {
		return []*diagnostic.Error{{
			Token:   usesKV.Value.GetToken(),
			Message: fmt.Sprintf("action %q must be pinned to a full length commit SHA", usesValue),
		}}
	}

	return nil
}
