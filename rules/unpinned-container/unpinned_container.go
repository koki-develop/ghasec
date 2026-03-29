package unpinnedcontainer

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unpinned-container"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "Container image tags are mutable. A compromised or updated registry image can change the contents behind a tag, executing different code silently on the next run"
}

func (r *Rule) Fix() string {
	return "Pin to the image digest using the @sha256:... suffix"
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return rules.CollectJobErrors(mapping.EachJob, checkJob)
}

func checkJob(_ *token.Token, job workflow.JobMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	errs = append(errs, checkContainer(job)...)
	errs = append(errs, checkServices(job)...)
	return errs
}

func checkContainer(job workflow.JobMapping) []*diagnostic.Error {
	kv := job.FindKey("container")
	if kv == nil {
		return nil
	}

	node := rules.UnwrapNode(kv.Value)

	// String form: container: ubuntu:22.04
	if rules.IsString(node) {
		value := rules.StringValue(node)
		if rules.IsExpressionNode(kv.Value) {
			return nil
		}
		if err := checkImage("container", value, kv.Value.GetToken()); err != nil {
			return []*diagnostic.Error{err}
		}
		return nil
	}

	// Mapping form: container: { image: ubuntu:22.04 }
	if m, ok := node.(*ast.MappingNode); ok {
		imageKV := (workflow.Mapping{MappingNode: m}).FindKey("image")
		if imageKV == nil {
			return nil
		}
		if rules.IsExpressionNode(imageKV.Value) {
			return nil
		}
		value := rules.StringValue(imageKV.Value)
		if err := checkImage("image", value, imageKV.Value.GetToken()); err != nil {
			return []*diagnostic.Error{err}
		}
	}

	return nil
}

func checkServices(job workflow.JobMapping) []*diagnostic.Error {
	kv := job.FindKey("services")
	if kv == nil {
		return nil
	}
	servicesNode := rules.UnwrapNode(kv.Value)
	servicesMapping, ok := servicesNode.(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	for _, entry := range servicesMapping.Values {
		serviceNode := rules.UnwrapNode(entry.Value)
		serviceMapping, ok := serviceNode.(*ast.MappingNode)
		if !ok {
			continue
		}
		imageKV := (workflow.Mapping{MappingNode: serviceMapping}).FindKey("image")
		if imageKV == nil {
			continue
		}
		if rules.IsExpressionNode(imageKV.Value) {
			continue
		}
		value := rules.StringValue(imageKV.Value)
		if err := checkImage("image", value, imageKV.Value.GetToken()); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func checkImage(subject, value string, tok *token.Token) *diagnostic.Error {
	if value == "" {
		return nil
	}
	if strings.Contains(value, "@sha256:") {
		return nil
	}
	return &diagnostic.Error{
		Token:   tok,
		Message: fmt.Sprintf("%q must be pinned to a digest", subject),
	}
}
