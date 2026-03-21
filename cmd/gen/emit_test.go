package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmitValidateFunc_UnknownKeyDetection verifies that the emitter generates
// correct unknown-key detection code when additionalProperties is false.
func TestEmitValidateFunc_UnknownKeyDetection(t *testing.T) {
	f := false
	node := &Node{
		Path:                 "branding",
		Types:                []string{"mapping"},
		AdditionalProperties: &f,
		Properties: map[string]*Node{
			"color": {Path: "branding.color", Types: []string{"string"}},
			"icon":  {Path: "branding.icon", Types: []string{"string"}},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateBranding", "workflow.WorkflowMapping", node)
	code := e.String()

	// Must define the function
	assert.Contains(t, code, "func ValidateBranding(m workflow.WorkflowMapping) []rules.ValidationError")

	// Must define a _knownKeys map containing the properties
	assert.Contains(t, code, `"color": true`)
	assert.Contains(t, code, `"icon": true`)

	// Must iterate mapping entries and check against known keys
	assert.Contains(t, code, "for _, _entry := range m.MappingNode.Values")
	assert.Contains(t, code, "_entry.Key.GetToken().Value")

	// Must append a ValidationError with KindUnknownKey
	assert.Contains(t, code, "rules.KindUnknownKey")
	assert.Contains(t, code, "rules.ValidationError{")
}

// TestEmitValidateFunc_RequiredKeyCheck verifies required key validation is emitted.
func TestEmitValidateFunc_RequiredKeyCheck(t *testing.T) {
	node := &Node{
		Path:     "runs",
		Types:    []string{"mapping"},
		Required: []string{"using"},
		Properties: map[string]*Node{
			"using": {Path: "runs.using", Types: []string{"string"}},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateRuns", "workflow.ActionMapping", node)
	code := e.String()

	// Must check for required key "using"
	assert.Contains(t, code, `"using"`)
	assert.Contains(t, code, "rules.KindRequiredKey")
	assert.Contains(t, code, "FindKey")
}

// TestEmitValidateFunc_EnumCheck verifies enum validation is emitted.
func TestEmitValidateFunc_EnumCheck(t *testing.T) {
	node := &Node{
		Path:  "branding.color",
		Types: []string{"string"},
		Enum:  []string{"white", "blue", "green"},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateBrandingColor", "workflow.WorkflowMapping", node)
	code := e.String()

	// Must reference the enum values
	assert.Contains(t, code, `"white"`)
	assert.Contains(t, code, `"blue"`)
	assert.Contains(t, code, `"green"`)

	// Must use KindInvalidEnum
	assert.Contains(t, code, "rules.KindInvalidEnum")
	assert.Contains(t, code, "rules.StringValue(")
}

// TestEmitValidateFunc_TypeCheck verifies type mismatch detection is emitted.
func TestEmitValidateFunc_TypeCheck(t *testing.T) {
	node := &Node{
		Path:  "jobs.build.timeout-minutes",
		Types: []string{"integer"},
		Properties: map[string]*Node{
			"timeout-minutes": {Path: "jobs.build.timeout-minutes", Types: []string{"integer"}},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateTimeoutMinutes", "workflow.WorkflowMapping", node)
	code := e.String()

	assert.Contains(t, code, "rules.KindTypeMismatch")
	assert.Contains(t, code, "rules.NodeTypeName(")
	assert.Contains(t, code, "rules.IsNumber(")
}

// TestEmitValidateFunc_ExpressionBypass verifies that expression nodes bypass validation.
func TestEmitValidateFunc_ExpressionBypass(t *testing.T) {
	node := &Node{
		Path:  "env",
		Types: []string{"string"},
		Enum:  []string{"value1", "value2"},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateEnvValue", "workflow.WorkflowMapping", node)
	code := e.String()

	assert.Contains(t, code, "rules.IsExpressionNode(")
}

// TestEmitValidateFunc_NoAdditionalPropertiesConstraint verifies that when
// additionalProperties is not set to false, no unknown-key loop is emitted.
func TestEmitValidateFunc_NoAdditionalPropertiesConstraint(t *testing.T) {
	tr := true
	node := &Node{
		Path:                 "env",
		Types:                []string{"mapping"},
		AdditionalProperties: &tr, // allowed = true
		Properties: map[string]*Node{
			"FOO": {Path: "env.FOO", Types: []string{"string"}},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateEnv", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should NOT emit unknown-key detection
	assert.NotContains(t, code, "rules.KindUnknownKey")
}

// TestSanitizeIdent verifies the ident sanitizer handles hyphens and special chars.
func TestSanitizeIdent(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"timeout-minutes", "timeout_minutes"},
		{"runs-on", "runs_on"},
		{"color", "color"},
		{"FOO_BAR", "FOO_BAR"},
		{"key.name", "key_name"},
	}
	for _, tc := range cases {
		result := sanitizeIdent(tc.input)
		assert.Equal(t, tc.expected, result, "sanitizeIdent(%q)", tc.input)
	}
}

// TestEmitValidateFunc_MultipleAllowedTypes verifies that multiple allowed types
// generate a combined condition.
func TestEmitValidateFunc_MultipleAllowedTypes(t *testing.T) {
	node := &Node{
		Path:  "permissions",
		Types: []string{"string", "mapping"},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidatePermissions", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should contain both type checks joined with &&
	assert.Contains(t, code, "rules.IsString(")
	assert.Contains(t, code, "rules.IsMapping(")

	// The combined condition should use &&
	assert.True(t, strings.Contains(code, "&&"), "expected && in combined type check")
}

// TestEmitOneOf_TypeOnly merges types from all branches into a single type check.
func TestEmitOneOf_TypeOnly(t *testing.T) {
	node := &Node{
		Path: "value",
		Properties: map[string]*Node{
			"val": {
				Path: "value.val",
				OneOf: []*Node{
					{Path: "value.val", Types: []string{"boolean"}},
					{Path: "value.val", Types: []string{"string"}},
				},
			},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateTypeOnly", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should merge types and emit a combined type check
	assert.Contains(t, code, "rules.IsBoolean(")
	assert.Contains(t, code, "rules.IsString(")
	assert.Contains(t, code, "rules.KindTypeMismatch")

	// Balanced braces
	assert.Equal(t, strings.Count(code, "{"), strings.Count(code, "}"), "unbalanced braces:\n%s", code)
}

// TestEmitOneOf_TypeBranching emits type-switching code.
func TestEmitOneOf_TypeBranching(t *testing.T) {
	f := false
	node := &Node{
		Path: "parent",
		Properties: map[string]*Node{
			"concurrency": {
				Path: "concurrency",
				OneOf: []*Node{
					{Path: "concurrency", Types: []string{"string"}},
					{
						Path:                 "concurrency",
						Types:                []string{"mapping"},
						AdditionalProperties: &f,
						Properties: map[string]*Node{
							"group": {Path: "concurrency.group", Types: []string{"string"}},
						},
					},
				},
			},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateTypeBranching", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should emit type branching
	assert.Contains(t, code, "oneOf type branching")
	assert.Contains(t, code, "rules.IsString(")
	assert.Contains(t, code, "rules.IsMapping(")
	assert.Contains(t, code, `"group": true`)

	// Balanced braces
	assert.Equal(t, strings.Count(code, "{"), strings.Count(code, "}"), "unbalanced braces:\n%s", code)
}

// TestEmitOneOf_DiscrimEnum emits discriminator-based branching using enum values.
func TestEmitOneOf_DiscrimEnum(t *testing.T) {
	jsConst := "node20"
	compositeConst := "composite"
	f := false
	node := &Node{
		Path: "parent",
		Properties: map[string]*Node{
			"runs": {
				Path: "runs",
				OneOf: []*Node{
					{
						Path:                 "runs",
						Types:                []string{"mapping"},
						AdditionalProperties: &f,
						Required:             []string{"using", "main"},
						Properties: map[string]*Node{
							"using": {Path: "runs.using", Const: &jsConst},
							"main":  {Path: "runs.main", Types: []string{"string"}},
						},
					},
					{
						Path:                 "runs",
						Types:                []string{"mapping"},
						AdditionalProperties: &f,
						Required:             []string{"using", "steps"},
						Properties: map[string]*Node{
							"using": {Path: "runs.using", Const: &compositeConst},
							"steps": {Path: "runs.steps", Types: []string{"sequence"}},
						},
					},
				},
			},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateDiscrimEnum", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should emit discriminator-based branching
	assert.Contains(t, code, `oneOf discriminator on "using"`)
	assert.Contains(t, code, `"node20"`)
	assert.Contains(t, code, `"composite"`)
	assert.Contains(t, code, "FindKey")

	// Balanced braces
	assert.Equal(t, strings.Count(code, "{"), strings.Count(code, "}"), "unbalanced braces:\n%s", code)
}

// TestEmitOneOf_DiscrimPresent emits presence-based discriminator branching.
func TestEmitOneOf_DiscrimPresent(t *testing.T) {
	node := &Node{
		Path: "parent",
		Properties: map[string]*Node{
			"job": {
				Path: "job",
				OneOf: []*Node{
					{
						Path:     "job",
						Required: []string{"runs-on"},
						Properties: map[string]*Node{
							"runs-on": {Path: "job.runs-on", Types: []string{"string"}},
						},
					},
					{
						Path:     "job",
						Required: []string{"uses"},
						Properties: map[string]*Node{
							"uses": {Path: "job.uses", Types: []string{"string"}},
						},
					},
				},
			},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateDiscrimPresent", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should emit presence-based branching
	assert.Contains(t, code, "oneOf presence-based branching")
	assert.Contains(t, code, `FindKey("runs-on")`)
	assert.Contains(t, code, `FindKey("uses")`)

	// Balanced braces
	assert.Equal(t, strings.Count(code, "{"), strings.Count(code, "}"), "unbalanced braces:\n%s", code)
}

// TestEmitIfThenElse emits conditional validation code.
func TestEmitIfThenElse(t *testing.T) {
	typeConst := "boolean"
	node := &Node{
		Path: "parent",
		Properties: map[string]*Node{
			"input": {
				Path: "input",
				If: &Node{
					Path: "input",
					Properties: map[string]*Node{
						"type": {Path: "input.type", Const: &typeConst},
					},
				},
				Then: &Node{
					Path: "input",
					Properties: map[string]*Node{
						"default": {Path: "input.default", Types: []string{"boolean"}},
					},
				},
			},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateIfThenElse", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should emit if/then/else
	assert.Contains(t, code, `if/then/else on "type" == "boolean"`)
	assert.Contains(t, code, `FindKey("type")`)

	// Balanced braces
	assert.Equal(t, strings.Count(code, "{"), strings.Count(code, "}"), "unbalanced braces:\n%s", code)
}

// TestEmitAllOf validates against all sub-schemas.
func TestEmitAllOf(t *testing.T) {
	node := &Node{
		Path: "parent",
		Properties: map[string]*Node{
			"event": {
				Path: "event",
				AllOf: []*Node{
					{
						Path:  "event",
						Types: []string{"mapping"},
						Properties: map[string]*Node{
							"branches": {Path: "event.branches", Types: []string{"sequence"}},
						},
					},
				},
			},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateAllOf", "workflow.WorkflowMapping", node)
	code := e.String()

	// Should emit the sub-schema checks
	assert.Contains(t, code, "rules.IsMapping(")
	assert.Contains(t, code, `FindKey("branches")`)

	// Balanced braces
	assert.Equal(t, strings.Count(code, "{"), strings.Count(code, "}"), "unbalanced braces:\n%s", code)
}

// TestClassifyOneOf verifies classification of oneOf patterns.
func TestClassifyOneOf(t *testing.T) {
	t.Run("type only", func(t *testing.T) {
		branches := []*Node{
			{Types: []string{"string"}},
			{Types: []string{"boolean"}},
		}
		assert.Equal(t, oneOfTypeOnly, classifyOneOf(branches))
	})

	t.Run("type branching", func(t *testing.T) {
		f := false
		branches := []*Node{
			{Types: []string{"string"}},
			{Types: []string{"mapping"}, AdditionalProperties: &f, Properties: map[string]*Node{"a": {}}},
		}
		assert.Equal(t, oneOfTypeBranching, classifyOneOf(branches))
	})

	t.Run("discrim enum", func(t *testing.T) {
		c1 := "a"
		c2 := "b"
		branches := []*Node{
			{Properties: map[string]*Node{"key": {Const: &c1}}},
			{Properties: map[string]*Node{"key": {Const: &c2}}},
		}
		assert.Equal(t, oneOfDiscrimEnum, classifyOneOf(branches))
	})

	t.Run("discrim present", func(t *testing.T) {
		branches := []*Node{
			{Required: []string{"runs-on"}},
			{Required: []string{"uses"}},
		}
		assert.Equal(t, oneOfDiscrimPresent, classifyOneOf(branches))
	})

	t.Run("empty branches are type-only", func(t *testing.T) {
		// Empty branches (e.g., expression syntax refs) are type-only with zero types.
		branches := []*Node{
			{},
			{},
		}
		assert.Equal(t, oneOfTypeOnly, classifyOneOf(branches))
	})

	t.Run("empty slice", func(t *testing.T) {
		assert.Equal(t, oneOfUnhandled, classifyOneOf(nil))
	})
}

// TestEmitValidateFunc_GeneratesCompilableCode verifies the emitter output is
// syntactically coherent (balanced braces).
func TestEmitValidateFunc_GeneratesCompilableCode(t *testing.T) {
	f := false
	node := &Node{
		Path:                 "branding",
		Types:                []string{"mapping"},
		AdditionalProperties: &f,
		Required:             []string{"using"},
		Properties: map[string]*Node{
			"color": {
				Path:  "branding.color",
				Types: []string{"string"},
				Enum:  []string{"white", "blue"},
			},
			"icon": {
				Path:  "branding.icon",
				Types: []string{"string"},
			},
		},
	}

	e := &emitter{}
	e.EmitValidateFunc("ValidateBranding", "workflow.WorkflowMapping", node)
	code := e.String()

	// Verify balanced braces
	openCount := strings.Count(code, "{")
	closeCount := strings.Count(code, "}")
	require.Equal(t, openCount, closeCount, "unbalanced braces in generated code:\n%s", code)
}
