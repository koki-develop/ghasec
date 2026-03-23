package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// extractEventTypeEnums reads the raw JSON schema file and extracts per-event
// activity type enums that are lost during compilation because they are defined
// as sibling properties alongside $ref (which overrides all siblings in
// draft-07).
//
// Returns a map from event name to allowed activity types, e.g.:
//
//	{"pull_request": ["opened", "closed", ...], "release": ["published", ...]}
func extractEventTypeEnums(schemaPath string) (map[string][]string, error) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("reading raw schema: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing raw schema: %w", err)
	}

	// Navigate to properties.on.oneOf[2].properties (the event mapping branch).
	// These return errors rather than (nil, nil) because this is a code
	// generator — silent degradation is worse than a build failure.
	onOneOf, ok := navigatePath(raw, "properties", "on", "oneOf")
	if !ok {
		return nil, fmt.Errorf("schema structure changed: missing properties.on.oneOf path")
	}
	oneOfArr, ok := onOneOf.([]any)
	if !ok || len(oneOfArr) < 3 {
		return nil, fmt.Errorf("schema structure changed: properties.on.oneOf has fewer than 3 branches")
	}
	eventBranch, ok := oneOfArr[2].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema structure changed: properties.on.oneOf[2] is not an object")
	}
	eventProps, ok := eventBranch["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema structure changed: properties.on.oneOf[2].properties is missing")
	}

	result := make(map[string][]string)
	for eventName, eventDef := range eventProps {
		eventObj, ok := eventDef.(map[string]any)
		if !ok {
			continue
		}
		enums := findTypesEnum(eventObj)
		if len(enums) > 0 {
			result[eventName] = enums
		}
	}

	return result, nil
}

// findTypesEnum searches an event definition for the types property enum.
// It handles two structural patterns:
//   - Direct: eventObj.properties.types has $ref + items.enum
//   - Nested: eventObj.oneOf[].allOf[].properties.types has $ref + items.enum
func findTypesEnum(eventObj map[string]any) []string {
	// Try direct pattern first
	if enums := extractTypesEnumFromProperties(eventObj); len(enums) > 0 {
		return enums
	}

	// Try nested pattern: oneOf -> allOf -> properties
	if oneOf, ok := eventObj["oneOf"].([]any); ok {
		for _, branch := range oneOf {
			branchObj, ok := branch.(map[string]any)
			if !ok {
				continue
			}
			if allOf, ok := branchObj["allOf"].([]any); ok {
				for _, item := range allOf {
					itemObj, ok := item.(map[string]any)
					if !ok {
						continue
					}
					if enums := extractTypesEnumFromProperties(itemObj); len(enums) > 0 {
						return enums
					}
				}
			}
		}
	}

	return nil
}

// extractTypesEnumFromProperties extracts enum values from obj.properties.types
// when the types property has both $ref and items.enum.
func extractTypesEnumFromProperties(obj map[string]any) []string {
	props, ok := obj["properties"].(map[string]any)
	if !ok {
		return nil
	}
	typesObj, ok := props["types"].(map[string]any)
	if !ok {
		return nil
	}
	// Must have $ref (indicating this is a draft-07 sibling situation)
	if _, hasRef := typesObj["$ref"]; !hasRef {
		return nil
	}
	// Extract items.enum
	items, ok := typesObj["items"].(map[string]any)
	if !ok {
		return nil
	}
	enumArr, ok := items["enum"].([]any)
	if !ok {
		return nil
	}
	var enums []string
	for _, v := range enumArr {
		if s, ok := v.(string); ok {
			enums = append(enums, s)
		}
	}
	return enums
}

// navigatePath traverses a nested map structure following the given key path.
func navigatePath(obj map[string]any, keys ...string) (any, bool) {
	var current any = obj
	for _, key := range keys {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// injectEventTypeEnums applies the extracted per-event type enums to the
// converted IR tree. For each event that has a types constraint, it finds
// the corresponding types property Items node and sets its Enum field.
func injectEventTypeEnums(root *Node, enums map[string][]string) error {
	if root == nil || len(enums) == 0 {
		return nil
	}

	// Find the "on" property node
	onNode, ok := root.Properties["on"]
	if !ok || onNode == nil {
		return fmt.Errorf("IR has no \"on\" property; cannot inject event type enums")
	}

	// Event properties can be in oneOf branches, allOf branches, or direct properties.
	// Search all of them.
	injectIntoNode(onNode, enums)
	return nil
}

// injectIntoNode recursively searches for event nodes and injects type enums.
func injectIntoNode(node *Node, enums map[string][]string) {
	if node == nil {
		return
	}

	// Check direct properties for event names
	for eventName, allowedTypes := range enums {
		if eventNode, ok := node.Properties[eventName]; ok {
			injectTypesEnumIntoEvent(eventNode, allowedTypes)
		}
	}

	// Recurse into combiners
	for _, branch := range node.OneOf {
		injectIntoNode(branch, enums)
	}
	for _, branch := range node.AllOf {
		injectIntoNode(branch, enums)
	}
	for _, branch := range node.AnyOf {
		injectIntoNode(branch, enums)
	}
}

// injectTypesEnumIntoEvent ensures the event node has a "types" property with
// items enum. Handles two cases:
//   - Event already has properties.types (e.g., pull_request via oneOf→allOf):
//     inject enum into existing Items node.
//   - Event has NO properties.types (e.g., branch_protection_rule where
//     event-level $ref wiped siblings): create the types property with Items.
func injectTypesEnumIntoEvent(eventNode *Node, allowedTypes []string) {
	if eventNode == nil {
		return
	}

	// Try to find and inject into existing types property
	if setItemsEnumRecursive(eventNode, allowedTypes) {
		return
	}

	// No existing types property found — the event-level $ref wiped all
	// properties. Create a types property with Items containing the enum.
	// The types property follows the #/definitions/types schema: oneOf of
	// {type: array, minItems: 1} and {type: string}. We inject items enum
	// into the array branch.
	if eventNode.Properties == nil {
		eventNode.Properties = make(map[string]*Node)
	}
	eventNode.Properties["types"] = &Node{
		Path: eventNode.Path + ".types",
		OneOf: []*Node{
			{
				Path:     eventNode.Path + ".types",
				Types:    []string{"sequence"},
				MinItems: 1,
				Items: &Node{
					Path: eventNode.Path + ".types.*",
					Enum: allowedTypes,
				},
			},
			{
				Path:  eventNode.Path + ".types",
				Types: []string{"string"},
				Enum:  allowedTypes,
			},
		},
	}
}

// setItemsEnumRecursive searches for an existing "types" property within a node
// (including combiners) and sets its items enum. Returns true if found.
func setItemsEnumRecursive(node *Node, allowedTypes []string) bool {
	if node == nil {
		return false
	}

	// Direct: node has properties.types
	if typesNode, ok := node.Properties["types"]; ok {
		return setItemsEnum(typesNode, allowedTypes)
	}

	// Recurse into combiners
	for _, branch := range node.OneOf {
		if setItemsEnumRecursive(branch, allowedTypes) {
			return true
		}
	}
	for _, branch := range node.AllOf {
		if setItemsEnumRecursive(branch, allowedTypes) {
			return true
		}
	}
	for _, branch := range node.AnyOf {
		if setItemsEnumRecursive(branch, allowedTypes) {
			return true
		}
	}
	return false
}

// setItemsEnum sets the Enum field on a types property node's Items.
// Returns true if the enum was successfully set on at least one branch.
func setItemsEnum(typesNode *Node, allowedTypes []string) bool {
	if typesNode == nil {
		return false
	}
	if typesNode.Items != nil {
		typesNode.Items.Enum = allowedTypes
		return true
	}
	// Search combiners within types node (types uses oneOf for array|string)
	set := false
	for _, branch := range typesNode.OneOf {
		if branch.Items != nil {
			branch.Items.Enum = allowedTypes
			set = true
		} else if hasType(branch, "sequence") {
			// The compiled schema has {type: sequence, minItems: 1} but no items
			// (because $ref sibling `items.enum` was discarded). Create Items.
			branch.Items = &Node{
				Path: branch.Path + ".*",
				Enum: allowedTypes,
			}
			set = true
		}
		// Also set enum on string branch
		if hasType(branch, "string") {
			branch.Enum = allowedTypes
			set = true
		}
	}
	for _, branch := range typesNode.AllOf {
		if setItemsEnum(branch, allowedTypes) {
			set = true
		}
	}
	return set
}

// hasType checks if a node has a specific type.
func hasType(node *Node, typeName string) bool {
	return slices.Contains(node.Types, typeName)
}
