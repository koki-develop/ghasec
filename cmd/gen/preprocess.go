package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// loadSchema reads a SchemaStore schema, applies the GitHub-compatibility
// overrides, makes the constraints written next to $ref effective, and
// compiles the result.
func loadSchema(path string, overrides []schemaOverride) (*jsonschema.Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Overrides match the upstream shape, so they run before $ref siblings
	// are rewritten.
	for _, o := range overrides {
		if err := o.apply(doc); err != nil {
			return nil, fmt.Errorf("override %q: %w", o.name, err)
		}
	}
	wrapRefSiblings(doc)

	// Re-read through the jsonschema decoder so that numbers have the type
	// the compiler expects.
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(path, v); err != nil {
		return nil, err
	}
	return c.Compile(path)
}

// annotationKeys are keywords that never affect validation. A $ref whose
// siblings are all annotations is left as is.
var annotationKeys = map[string]bool{
	"$comment":           true,
	"description":        true,
	"default":            true,
	"examples":           true,
	"title":              true,
	"deprecationMessage": true,
}

// wrapRefSiblings rewrites every schema that has constraints next to $ref
// into `allOf: [{$ref}, ...]` plus those constraints.
//
// In draft-07 the siblings of $ref are ignored, and the compiler follows the
// specification. SchemaStore validates its own test files with Ajv, which
// applies the siblings, and SchemaStore's schemas rely on that (for example,
// the activity types of each event are written next to
// `$ref: #/definitions/types`). Applying the siblings matches what the schema
// authors meant.
func wrapRefSiblings(v any) {
	switch v := v.(type) {
	case map[string]any:
		for _, child := range v {
			wrapRefSiblings(child)
		}
		ref, ok := v["$ref"]
		if !ok {
			return
		}
		hasConstraint := false
		for k := range v {
			if k != "$ref" && !annotationKeys[k] {
				hasConstraint = true
				break
			}
		}
		if !hasConstraint {
			return
		}
		delete(v, "$ref")
		allOf := []any{map[string]any{"$ref": ref}}
		if existing, ok := v["allOf"].([]any); ok {
			allOf = append(allOf, existing...)
		}
		v["allOf"] = allOf
	case []any:
		for _, child := range v {
			wrapRefSiblings(child)
		}
	}
}

// schemaOverride rewrites one part of an upstream schema where it differs
// from what GitHub accepts. Each apply checks that the upstream fragment
// still has the expected shape and returns an error otherwise, so that a
// SchemaStore update cannot silently turn an override into a no-op or apply
// it to something else.
type schemaOverride struct {
	name  string
	apply func(doc map[string]any) error
}

// workflowOverrides are applied to github-workflow.json. Keep the list in
// rules/AGENTS.md ("Schema Overrides") in sync.
var workflowOverrides = []schemaOverride{
	{"workflow_dispatch input type is optional", overrideDispatchInputType},
	{"event types accept a single string", overrideEventTypesString},
	{"image_version accepts types and single strings", overrideImageVersion},
	{"copilot-requests accepts none", overrideCopilotRequestsNone},
	{"workflow_call secret accepts null", overrideWorkflowCallSecretNull},
}

// actionOverrides are applied to github-action.json. Keep the list in
// rules/AGENTS.md ("Schema Overrides") in sync.
var actionOverrides = []schemaOverride{
	{"composite step requires run and shell, or uses", overrideCompositeStep},
}

func lookup(v any, path ...any) (any, error) {
	cur := v
	for i, p := range path {
		switch p := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%v: not an object", path[:i])
			}
			if cur, ok = m[p]; !ok {
				return nil, fmt.Errorf("%v: missing", path[:i+1])
			}
		case int:
			a, ok := cur.([]any)
			if !ok || p >= len(a) {
				return nil, fmt.Errorf("%v: missing", path[:i+1])
			}
			cur = a[p]
		}
	}
	return cur, nil
}

func lookupMap(v any, path ...any) (map[string]any, error) {
	x, err := lookup(v, path...)
	if err != nil {
		return nil, err
	}
	m, ok := x.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%v: not an object", path)
	}
	return m, nil
}

func mustParse(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	return v
}

func jsonEqual(a any, b string) bool {
	return reflect.DeepEqual(a, mustParse(b))
}

// overrideDispatchInputType: upstream requires "type" on every
// workflow_dispatch input (oneOf with required ["type"]). GitHub treats an
// input without "type" as a string, so the per-type constraints are only
// applied when "type" is present, as in the previous upstream schema.
func overrideDispatchInputType(doc map[string]any) error {
	input, err := lookupMap(doc, "definitions", "workflowDispatchInput")
	if err != nil {
		return err
	}
	if _, ok := input["allOf"]; ok {
		return fmt.Errorf("workflowDispatchInput.allOf: unexpected")
	}
	if !jsonEqual(input["oneOf"], `[
		{"type": "object", "properties": {"type": {"const": "string"}, "default": {"type": "string"}}, "required": ["type"]},
		{"type": "object", "properties": {"type": {"const": "boolean"}, "default": {"type": "boolean"}}, "required": ["type"]},
		{"type": "object", "properties": {"type": {"const": "number"}, "default": {"type": "number"}}, "required": ["type"]},
		{"type": "object", "properties": {"type": {"const": "environment"}, "default": {"type": "string"}}, "required": ["type"]},
		{"type": "object", "properties": {"type": {"const": "choice"}, "options": {"$ref": "#/definitions/workflowDispatchInput/properties/options"}}, "required": ["type", "options"]}
	]`) {
		return fmt.Errorf("workflowDispatchInput.oneOf: unexpected shape")
	}

	delete(input, "oneOf")
	input["allOf"] = mustParse(`[
		{"if": {"properties": {"type": {"const": "string"}}, "required": ["type"]}, "then": {"properties": {"default": {"type": "string"}}}},
		{"if": {"properties": {"type": {"const": "boolean"}}, "required": ["type"]}, "then": {"properties": {"default": {"type": "boolean"}}}},
		{"if": {"properties": {"type": {"const": "number"}}, "required": ["type"]}, "then": {"properties": {"default": {"type": "number"}}}},
		{"if": {"properties": {"type": {"const": "environment"}}, "required": ["type"]}, "then": {"properties": {"default": {"type": "string"}}}},
		{"if": {"properties": {"type": {"const": "choice"}}, "required": ["type"]}, "then": {"required": ["options"]}}
	]`)
	return nil
}

// overrideEventTypesString: each event's "types" refers to
// #/definitions/types (a sequence or a single string) but also says
// `"type": "array"` next to it. GitHub accepts a single string, so the
// sibling "type" is dropped and the "items" enum stays.
func overrideEventTypesString(doc map[string]any) error {
	events, err := lookupMap(doc, "properties", "on", "oneOf", 2, "properties")
	if err != nil {
		return err
	}
	n := 0
	var unexpected []any
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if v["$ref"] == "#/definitions/types" {
				if v["type"] != "array" {
					unexpected = append(unexpected, v["type"])
					return
				}
				delete(v, "type")
				n++
			}
			for _, c := range v {
				walk(c)
			}
		case []any:
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(events)
	if len(unexpected) > 0 {
		return fmt.Errorf(`event "types" with $ref #/definitions/types: expected type array, got %v`, unexpected)
	}
	if n == 0 {
		return fmt.Errorf(`no event "types" with $ref #/definitions/types and type array`)
	}
	return nil
}

// overrideImageVersion: upstream lists only "names" and "versions" as
// sequences of strings. GitHub also accepts "types" (created, ready,
// deleted), a single value for each of the three, and numbers and booleans
// in "names" and "versions" (GitHub reads them as strings).
func overrideImageVersion(doc map[string]any) error {
	ev, err := lookupMap(doc, "properties", "on", "oneOf", 2, "properties", "image_version")
	if err != nil {
		return err
	}
	branches, ok := ev["oneOf"].([]any)
	if !ok || len(branches) != 2 || !jsonEqual(branches[0], `{"type": "null"}`) {
		return fmt.Errorf("image_version.oneOf: expected [null, object]")
	}
	obj, ok := branches[1].(map[string]any)
	if !ok || obj["type"] != "object" || obj["additionalProperties"] != false {
		return fmt.Errorf("image_version.oneOf[1]: expected a closed object")
	}
	props, ok := obj["properties"].(map[string]any)
	if !ok || len(props) != 2 {
		return fmt.Errorf("image_version properties: expected names and versions only")
	}
	for _, k := range []string{"names", "versions"} {
		p, ok := props[k].(map[string]any)
		if !ok || p["type"] != "array" || !jsonEqual(p["items"], `{"type": "string"}`) {
			return fmt.Errorf("image_version.%s: expected a sequence of strings", k)
		}
	}

	branches[1] = mustParse(`{
		"type": "object",
		"properties": {
			"names": {"oneOf": [
				{"type": ["string", "number", "boolean"]},
				{"type": "array", "items": {"type": ["string", "number", "boolean"]}, "minItems": 1}
			]},
			"versions": {"oneOf": [
				{"type": ["string", "number", "boolean"]},
				{"type": "array", "items": {"type": ["string", "number", "boolean"]}, "minItems": 1}
			]},
			"types": {"oneOf": [
				{"type": "string", "enum": ["created", "ready", "deleted"]},
				{"type": "array", "items": {"type": "string", "enum": ["created", "ready", "deleted"]}}
			]}
		},
		"additionalProperties": false
	}`)
	return nil
}

// overrideCopilotRequestsNone: upstream allows only "write" for the
// copilot-requests permission. GitHub also accepts "none".
func overrideCopilotRequestsNone(doc map[string]any) error {
	p, err := lookupMap(doc, "definitions", "permissions-event", "properties", "copilot-requests")
	if err != nil {
		return err
	}
	if !jsonEqual(p["enum"], `["write"]`) {
		return fmt.Errorf(`copilot-requests.enum: expected ["write"]`)
	}
	p["enum"] = []any{"write", "none"}
	return nil
}

// overrideWorkflowCallSecretNull: upstream requires each on.workflow_call
// secret to be a mapping. GitHub also accepts a secret with no value
// (`token:`).
func overrideWorkflowCallSecretNull(doc map[string]any) error {
	secrets, err := lookupMap(doc, "properties", "on", "oneOf", 2, "properties", "workflow_call", "oneOf", 1, "properties", "secrets", "patternProperties")
	if err != nil {
		return err
	}
	if len(secrets) != 1 {
		return fmt.Errorf("workflow_call secrets.patternProperties: expected one pattern")
	}
	for _, v := range secrets {
		secret, ok := v.(map[string]any)
		if !ok || secret["type"] != "object" || secret["additionalProperties"] != false {
			return fmt.Errorf("workflow_call secret: expected a closed object")
		}
		props, ok := secret["properties"].(map[string]any)
		if !ok || len(props) != 2 || props["description"] == nil || props["required"] == nil {
			return fmt.Errorf("workflow_call secret properties: expected description and required only")
		}
		secret["type"] = []any{"null", "object"}
	}
	return nil
}

// overrideCompositeStep: upstream writes "run and shell, or uses" with `not`,
// which the generator cannot validate. This is the same condition written
// with required.
func overrideCompositeStep(doc map[string]any) error {
	items, err := lookupMap(doc, "definitions", "runs-composite", "properties", "steps", "items")
	if err != nil {
		return err
	}
	if !jsonEqual(items["oneOf"], `[
		{"anyOf": [
			{"not": {"properties": {"run": true}, "required": ["run"]}},
			{"not": {"properties": {"shell": true}, "required": ["shell"]}}
		]},
		{"not": {"properties": {"uses": true}, "required": ["uses"]}}
	]`) {
		return fmt.Errorf("runs-composite steps.items.oneOf: unexpected shape")
	}
	items["oneOf"] = mustParse(`[{"required": ["run", "shell"]}, {"required": ["uses"]}]`)
	return nil
}
