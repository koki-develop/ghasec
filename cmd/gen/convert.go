package main

import (
	"fmt"
	"os"

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
var skipPaths = map[string]bool{}

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

// apSchemaCache caches converted additionalProperties schemas to avoid OOM
// when the same schema is referenced from multiple locations.
var apSchemaCache = map[*jsonschema.Schema]*Node{}

// convertVisiting tracks schemas currently being converted to detect circular refs.
var convertVisiting = map[*jsonschema.Schema]bool{}

// convert transforms a compiled *jsonschema.Schema into our *Node IR.
// path is the dot-separated location for diagnostic purposes (e.g. "jobs.*.steps.*").
func convert(s *jsonschema.Schema, path string) *Node {
	if s == nil {
		return nil
	}

	// Resolve $ref to the target schema.
	s = resolveRef(s)

	// Detect circular references.
	if convertVisiting[s] {
		return nil
	}
	convertVisiting[s] = true
	defer delete(convertVisiting, s)

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
			// Use "*" as the path segment for pattern properties (not the raw regex)
			childPath := "*"
			if path != "" {
				childPath = path + ".*"
			}
			node.PatternProps[pattern] = convert(v, childPath)
		}
	}

	// AdditionalProperties
	switch ap := s.AdditionalProperties.(type) {
	case bool:
		node.AdditionalProperties = &ap
	case *jsonschema.Schema:
		t := true
		node.AdditionalProperties = &t
		// G1: Convert additionalProperties schema for value validation.
		// Cache AP schemas to avoid OOM from repeated conversion of shared definitions.
		apResolved := resolveRef(ap)
		if cached, ok := apSchemaCache[apResolved]; ok {
			node.AdditionalPropsSchema = cached
		} else {
			apNode := convert(ap, path+".*")
			if apNode != nil && nodeHasAnyIRChecks(apNode) {
				node.AdditionalPropsSchema = apNode
				apSchemaCache[apResolved] = apNode
			}
		}
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

	// G4: MinItems / MinProperties
	if s.MinItems != nil {
		node.MinItems = *s.MinItems
	}
	if s.MinProperties != nil {
		node.MinProperties = *s.MinProperties
	}

	// G5: String pattern
	if s.Pattern != nil {
		node.Pattern = s.Pattern.String()
	}

	// V3: Property dependencies
	if s.Dependencies != nil {
		for prop, dep := range s.Dependencies {
			if reqd, ok := dep.([]string); ok {
				if node.Dependencies == nil {
					node.Dependencies = make(map[string][]string)
				}
				node.Dependencies[prop] = reqd
			} else {
				fmt.Fprintf(os.Stderr, "warning: unsupported dependency type %T for property %q at path %q (skipped)\n", dep, prop, path)
			}
		}
	}

	// Combiners
	for _, sub := range s.OneOf {
		node.OneOf = append(node.OneOf, convert(sub, path))
	}
	// G3: For allOf, filter out `not` sub-schemas. We can't validate them,
	// but we can still validate the remaining constraints. This enables
	// push/pull_request/pull_request_target events to get type/key validation.
	for _, sub := range s.AllOf {
		if sub.Not == nil {
			node.AllOf = append(node.AllOf, convert(sub, path))
		}
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

// nodeHasAnyIRChecks returns true if a node has any validation constraints.
func nodeHasAnyIRChecks(n *Node) bool {
	if n == nil {
		return false
	}
	return len(n.Types) > 0 || len(n.Enum) > 0 || n.Const != nil ||
		len(n.Properties) > 0 || len(n.Required) > 0 ||
		n.Items != nil || len(n.PatternProps) > 0 ||
		len(n.OneOf) > 0 || len(n.AllOf) > 0 || len(n.AnyOf) > 0 ||
		n.If != nil || n.Pattern != "" || len(n.Dependencies) > 0
}
