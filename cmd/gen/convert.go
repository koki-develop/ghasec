package main

import (
	"fmt"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// jsonTypeToYAML maps JSON Schema type names to YAML-oriented equivalents.
func jsonTypeToYAML(t string) string {
	switch t {
	case "object":
		return "mapping"
	case "array":
		return "sequence"
	case "string":
		return "string"
	case "boolean":
		return "boolean"
	case "integer":
		return "integer"
	case "number":
		return "number"
	case "null":
		return "null"
	default:
		return t
	}
}

// annotations maps schema paths to parent/context terms for context-rich error messages.
// For example, "permissions" gets Parent="permissions", ContextTerm="scope" so that
// unknown key errors say `"permissions" has unknown scope "foo"` instead of generic messages.
var annotations = map[string]struct{ parent, context string }{
	"permissions":        {"permissions", "scope"},
	"jobs.*.permissions": {"permissions", "scope"},
	"on":                 {"on", "event"},
	"branding":           {"branding", ""},
	"branding.color":     {"branding", "color"},
	"branding.icon":      {"branding", "icon"},
}

// skipPaths lists schema paths whose children should not be recursively validated
// by the generated code because they are handled by dedicated validation logic.
var skipPaths = map[string]bool{
	"jobs.*.steps": true, // workflow steps — handled by step.CheckEntries()
	"runs.steps":   true, // action composite steps — handled by step.CheckEntries()
}

// resolveRef follows $ref chains to the actual schema definition.
// If s has a Ref and no direct constraints, return the Ref target.
func resolveRef(s *jsonschema.Schema) *jsonschema.Schema {
	if s == nil {
		return nil
	}
	// Follow $ref if the schema itself has no direct constraints.
	// A pure $ref schema has Ref set and no Types/Properties/etc of its own.
	if s.Ref != nil && s.Types == nil && len(s.Properties) == 0 &&
		len(s.Required) == 0 && s.Enum == nil && s.Const == nil &&
		len(s.OneOf) == 0 && len(s.AllOf) == 0 && len(s.AnyOf) == 0 &&
		s.If == nil && s.Items == nil && len(s.PatternProperties) == 0 {
		return resolveRef(s.Ref)
	}
	return s
}

// convert transforms a compiled *jsonschema.Schema into our *Node IR.
// path is the dot-separated location for diagnostic purposes (e.g. "jobs.*.steps.*").
func convert(s *jsonschema.Schema, path string) *Node {
	if s == nil {
		return nil
	}

	// Resolve $ref to the target schema.
	s = resolveRef(s)

	node := &Node{Path: path}

	// Types
	if s.Types != nil {
		for _, t := range s.Types.ToStrings() {
			node.Types = append(node.Types, jsonTypeToYAML(t))
		}
	}

	// Required
	node.Required = append(node.Required, s.Required...)

	// Enum
	if s.Enum != nil {
		for _, v := range s.Enum.Values {
			node.Enum = append(node.Enum, fmt.Sprintf("%v", v))
		}
	}

	// Const
	if s.Const != nil {
		str := fmt.Sprintf("%v", *s.Const)
		node.Const = &str
	}

	// Properties
	if len(s.Properties) > 0 {
		node.Properties = make(map[string]*Node, len(s.Properties))
		for k, v := range s.Properties {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			node.Properties[k] = convert(v, childPath)
		}
	}

	// PatternProperties
	if len(s.PatternProperties) > 0 {
		node.PatternProps = make(map[string]*Node, len(s.PatternProperties))
		for re, v := range s.PatternProperties {
			pattern := re.String()
			childPath := pattern
			if path != "" {
				childPath = path + "." + pattern
			}
			node.PatternProps[pattern] = convert(v, childPath)
		}
	}

	// AdditionalProperties
	switch ap := s.AdditionalProperties.(type) {
	case bool:
		node.AdditionalProperties = &ap
	case *jsonschema.Schema:
		// If it's a schema, treat as allowed (true) — the sub-schema constrains values.
		t := true
		node.AdditionalProperties = &t
	}

	// Items — can be nil, *Schema, or []*Schema
	switch it := s.Items.(type) {
	case *jsonschema.Schema:
		itemPath := path + ".*"
		node.Items = convert(it, itemPath)
	case []*jsonschema.Schema:
		// Tuple validation — we only handle single-schema items for now.
		// Use the first schema as representative.
		if len(it) > 0 {
			itemPath := path + ".*"
			node.Items = convert(it[0], itemPath)
		}
	}

	// Combiners
	for _, sub := range s.OneOf {
		node.OneOf = append(node.OneOf, convert(sub, path))
	}
	for _, sub := range s.AllOf {
		node.AllOf = append(node.AllOf, convert(sub, path))
	}
	for _, sub := range s.AnyOf {
		node.AnyOf = append(node.AnyOf, convert(sub, path))
	}

	// If/Then/Else
	node.If = convert(s.If, path)
	node.Then = convert(s.Then, path)
	node.Else = convert(s.Else, path)

	// Apply annotations for context-rich error messages.
	if ann, ok := annotations[path]; ok {
		node.ParentName = ann.parent
		node.ContextTerm = ann.context
	}

	// Mark paths that should skip child validation.
	if skipPaths[path] {
		node.SkipChildren = true
	}

	return node
}
