package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var v map[string]any
	require.NoError(t, json.Unmarshal([]byte(s), &v))
	return v
}

func TestWrapRefSiblings_ConstraintSiblings(t *testing.T) {
	doc := mustJSON(t, `{"$ref": "#/definitions/a", "description": "d", "properties": {"x": {"type": "string"}}, "required": ["x"]}`)
	wrapRefSiblings(doc)

	assert.NotContains(t, doc, "$ref")
	assert.Equal(t, []any{map[string]any{"$ref": "#/definitions/a"}}, doc["allOf"])
	assert.Equal(t, []any{"x"}, doc["required"])
	assert.Contains(t, doc, "properties")
	assert.Equal(t, "d", doc["description"])
}

func TestWrapRefSiblings_AnnotationOnlySiblings(t *testing.T) {
	doc := mustJSON(t, `{"$ref": "#/definitions/a", "$comment": "c", "description": "d", "default": [], "examples": [], "title": "t", "deprecationMessage": "m"}`)
	wrapRefSiblings(doc)

	assert.Equal(t, "#/definitions/a", doc["$ref"])
	assert.NotContains(t, doc, "allOf")
}

func TestWrapRefSiblings_ExistingAllOf(t *testing.T) {
	doc := mustJSON(t, `{"$ref": "#/definitions/a", "allOf": [{"required": ["x"]}]}`)
	wrapRefSiblings(doc)

	assert.NotContains(t, doc, "$ref")
	assert.Equal(t, []any{
		map[string]any{"$ref": "#/definitions/a"},
		map[string]any{"required": []any{"x"}},
	}, doc["allOf"])
}

func TestWrapRefSiblings_Nested(t *testing.T) {
	doc := mustJSON(t, `{"definitions": {"d": {"properties": {"p": {"oneOf": [{"type": "null"}, {"type": "object", "properties": {"types": {"$ref": "#/definitions/types", "items": {"enum": ["a"]}}}}]}}}}}`)
	wrapRefSiblings(doc)

	types := doc["definitions"].(map[string]any)["d"].(map[string]any)["properties"].(map[string]any)["p"].(map[string]any)["oneOf"].([]any)[1].(map[string]any)["properties"].(map[string]any)["types"].(map[string]any)
	assert.NotContains(t, types, "$ref")
	assert.Equal(t, []any{map[string]any{"$ref": "#/definitions/types"}}, types["allOf"])
	assert.Contains(t, types, "items")
}

// writeSchema writes a draft-07 schema document to a temporary file and
// returns its path.
func writeSchema(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "schema.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// TestLoadSchema_RefSiblingsApplied checks that constraints written next to
// $ref reach the IR together with the constraints of the $ref target, as
// SchemaStore's own validator (Ajv) applies them.
func TestLoadSchema_RefSiblingsApplied(t *testing.T) {
	path := writeSchema(t, `{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"definitions": {"base": {"type": "object", "properties": {"a": {"type": "string"}}}},
		"type": "object",
		"properties": {"x": {"$ref": "#/definitions/base", "required": ["a"], "additionalProperties": false}}
	}`)
	s, err := loadSchema(path, nil)
	require.NoError(t, err)

	x := convert(s, "").Properties["x"]
	require.NotNil(t, x)
	assert.Equal(t, []string{"a"}, x.Required)
	require.NotNil(t, x.AdditionalProperties)
	assert.False(t, *x.AdditionalProperties)
	require.Len(t, x.AllOf, 1)
	assert.Contains(t, x.AllOf[0].Properties, "a")
}

func readRawSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../schemastore/src/schemas/json", name))
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

func TestOverrides_ApplyToUpstreamSchemas(t *testing.T) {
	for _, o := range workflowOverrides {
		t.Run(o.name, func(t *testing.T) {
			assert.NoError(t, o.apply(readRawSchema(t, "github-workflow.json")))
		})
	}
	for _, o := range actionOverrides {
		t.Run(o.name, func(t *testing.T) {
			assert.NoError(t, o.apply(readRawSchema(t, "github-action.json")))
		})
	}
}

// TestOverrides_RejectUnexpectedShape checks that every override fails when
// the upstream fragment it rewrites is not in the shape it expects, so that
// a SchemaStore update cannot silently turn an override into a no-op.
func TestOverrides_RejectUnexpectedShape(t *testing.T) {
	cases := []struct {
		overrides []schemaOverride
		file      string
	}{
		{workflowOverrides, "github-workflow.json"},
		{actionOverrides, "github-action.json"},
	}
	for _, c := range cases {
		for _, o := range c.overrides {
			t.Run(o.name+"/missing", func(t *testing.T) {
				assert.Error(t, o.apply(map[string]any{}))
			})
			t.Run(o.name+"/already-changed", func(t *testing.T) {
				doc := readRawSchema(t, c.file)
				require.NoError(t, o.apply(doc))
				assert.Error(t, o.apply(doc))
			})
		}
	}
}

func TestOverrides_Effect(t *testing.T) {
	wf := readRawSchema(t, "github-workflow.json")
	for _, o := range workflowOverrides {
		require.NoError(t, o.apply(wf), o.name)
	}
	defs := wf["definitions"].(map[string]any)
	events := wf["properties"].(map[string]any)["on"].(map[string]any)["oneOf"].([]any)[2].(map[string]any)["properties"].(map[string]any)

	t.Run("workflow_dispatch input type is optional", func(t *testing.T) {
		input := defs["workflowDispatchInput"].(map[string]any)
		assert.NotContains(t, input, "oneOf")
		allOf := input["allOf"].([]any)
		require.Len(t, allOf, 5)
		for _, c := range allOf {
			// Each condition only applies when "type" is present.
			assert.Equal(t, []any{"type"}, c.(map[string]any)["if"].(map[string]any)["required"])
		}
	})

	t.Run("event types accept a single string", func(t *testing.T) {
		types := events["release"].(map[string]any)["oneOf"].([]any)[1].(map[string]any)["properties"].(map[string]any)["types"].(map[string]any)
		assert.NotContains(t, types, "type")
		assert.Equal(t, "#/definitions/types", types["$ref"])
	})

	t.Run("image_version accepts types and single strings", func(t *testing.T) {
		obj := events["image_version"].(map[string]any)["oneOf"].([]any)[1].(map[string]any)
		props := obj["properties"].(map[string]any)
		assert.Contains(t, props, "types")
		for _, k := range []string{"names", "versions", "types"} {
			assert.Len(t, props[k].(map[string]any)["oneOf"], 2, k)
		}
		scalars := []any{"string", "number", "boolean"}
		for _, k := range []string{"names", "versions"} {
			oneOf := props[k].(map[string]any)["oneOf"].([]any)
			assert.Equal(t, scalars, oneOf[0].(map[string]any)["type"], k)
			assert.Equal(t, scalars, oneOf[1].(map[string]any)["items"].(map[string]any)["type"], k)
		}
		assert.Equal(t, false, obj["additionalProperties"])
	})

	t.Run("workflow_call secret accepts null", func(t *testing.T) {
		secrets := events["workflow_call"].(map[string]any)["oneOf"].([]any)[1].(map[string]any)["properties"].(map[string]any)["secrets"].(map[string]any)
		for _, secret := range secrets["patternProperties"].(map[string]any) {
			assert.Equal(t, []any{"null", "object"}, secret.(map[string]any)["type"])
		}
		assert.Equal(t, "object", secrets["type"])
	})

	t.Run("copilot-requests accepts none", func(t *testing.T) {
		enum := defs["permissions-event"].(map[string]any)["properties"].(map[string]any)["copilot-requests"].(map[string]any)["enum"]
		assert.Equal(t, []any{"write", "none"}, enum)
	})

	act := readRawSchema(t, "github-action.json")
	for _, o := range actionOverrides {
		require.NoError(t, o.apply(act), o.name)
	}
	t.Run("composite step requires run and shell, or uses", func(t *testing.T) {
		items := act["definitions"].(map[string]any)["runs-composite"].(map[string]any)["properties"].(map[string]any)["steps"].(map[string]any)["items"].(map[string]any)
		assert.Equal(t, []any{
			map[string]any{"required": []any{"run", "shell"}},
			map[string]any{"required": []any{"uses"}},
		}, items["oneOf"])
	})
}

// TestOverrides_RejectChangedFragment checks that each override fails when
// the upstream fragment it rewrites differs slightly from the expected shape.
func TestOverrides_RejectChangedFragment(t *testing.T) {
	get := func(v any, path ...any) map[string]any {
		t.Helper()
		m, err := lookupMap(v, path...)
		require.NoError(t, err)
		return m
	}
	events := []any{"properties", "on", "oneOf", 2, "properties"}
	cases := []struct {
		override string
		file     string
		mutate   func(doc map[string]any)
	}{
		{"workflow_dispatch input type is optional", "github-workflow.json", func(doc map[string]any) {
			number := get(doc, "definitions", "workflowDispatchInput", "oneOf", 2, "properties", "default")
			number["type"] = "string"
		}},
		{"event types accept a single string", "github-workflow.json", func(doc map[string]any) {
			// Only one event changes; the others keep the expected shape.
			types := get(doc, append(events, "release", "oneOf", 1, "properties", "types")...)
			types["type"] = "string"
		}},
		{"image_version accepts types and single strings", "github-workflow.json", func(doc map[string]any) {
			props := get(doc, append(events, "image_version", "oneOf", 1, "properties")...)
			props["types"] = map[string]any{"type": "array"}
		}},
		{"workflow_call secret accepts null", "github-workflow.json", func(doc map[string]any) {
			secrets := get(doc, append(events, "workflow_call", "oneOf", 1, "properties", "secrets", "patternProperties")...)
			for _, secret := range secrets {
				secret.(map[string]any)["properties"].(map[string]any)["environment"] = map[string]any{"type": "string"}
			}
		}},
		{"copilot-requests accepts none", "github-workflow.json", func(doc map[string]any) {
			get(doc, "definitions", "permissions-event", "properties", "copilot-requests")["enum"] = []any{"write", "read"}
		}},
		{"composite step requires run and shell, or uses", "github-action.json", func(doc map[string]any) {
			not := get(doc, "definitions", "runs-composite", "properties", "steps", "items", "oneOf", 1, "not")
			not["required"] = []any{"run"}
		}},
	}

	all := map[string]schemaOverride{}
	for _, o := range append(append([]schemaOverride{}, workflowOverrides...), actionOverrides...) {
		all[o.name] = o
	}
	require.Len(t, cases, len(all), "every override needs a case")
	for _, c := range cases {
		t.Run(c.override, func(t *testing.T) {
			o, ok := all[c.override]
			require.True(t, ok)
			doc := readRawSchema(t, c.file)
			c.mutate(doc)
			assert.Error(t, o.apply(doc))
		})
	}
}
