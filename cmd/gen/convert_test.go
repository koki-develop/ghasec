package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvert_WorkflowTopLevel(t *testing.T) {
	schema, err := loadSchema("../../schemastore/src/schemas/json/github-workflow.json")
	require.NoError(t, err)

	node := convert(schema, "")
	require.NotNil(t, node)

	// Top-level type should be "mapping" (converted from "object")
	assert.Contains(t, node.Types, "mapping")

	// Known top-level properties must be present
	for _, prop := range []string{"name", "on", "jobs", "permissions"} {
		assert.Contains(t, node.Properties, prop, "expected property %q", prop)
	}

	// additionalProperties: false at top level
	require.NotNil(t, node.AdditionalProperties)
	assert.False(t, *node.AdditionalProperties)
}

func TestConvert_ActionTopLevel(t *testing.T) {
	schema, err := loadSchema("../../schemastore/src/schemas/json/github-action.json")
	require.NoError(t, err)

	node := convert(schema, "")
	require.NotNil(t, node)

	// Top-level type should be "mapping"
	assert.Contains(t, node.Types, "mapping")

	// Known top-level properties must be present
	for _, prop := range []string{"name", "runs", "inputs", "branding"} {
		assert.Contains(t, node.Properties, prop, "expected property %q", prop)
	}

	// required contains "runs"
	assert.Contains(t, node.Required, "runs")
}

func TestConvert_EnumExtraction(t *testing.T) {
	schema, err := loadSchema("../../schemastore/src/schemas/json/github-action.json")
	require.NoError(t, err)

	node := convert(schema, "")
	require.NotNil(t, node)

	branding := node.Properties["branding"]
	require.NotNil(t, branding, "branding property must exist")

	color := branding.Properties["color"]
	require.NotNil(t, color, "branding.color property must exist")

	// Enum should contain expected color values
	for _, expected := range []string{"white", "blue"} {
		assert.Contains(t, color.Enum, expected, "branding.color enum should contain %q", expected)
	}
	assert.NotEmpty(t, color.Enum)
}

func TestConvert_ActionRunsOneOf(t *testing.T) {
	schema, err := loadSchema("../../schemastore/src/schemas/json/github-action.json")
	require.NoError(t, err)

	node := convert(schema, "")
	require.NotNil(t, node)

	runs := node.Properties["runs"]
	require.NotNil(t, runs, "runs property must exist")

	// action runs has oneOf branches for different action types
	assert.NotEmpty(t, runs.OneOf, "runs should have oneOf branches")
}

func TestConvert_NilSchema(t *testing.T) {
	node := convert(nil, "")
	assert.Nil(t, node)
}

func TestConvert_TypeMapping(t *testing.T) {
	cases := []struct {
		jsonType string
		yamlType string
	}{
		{"object", "mapping"},
		{"array", "sequence"},
		{"string", "string"},
		{"boolean", "boolean"},
		{"integer", "integer"},
		{"number", "number"},
		{"null", "null"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.yamlType, jsonTypeToYAML(tc.jsonType))
	}
}
