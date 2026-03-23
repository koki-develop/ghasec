package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// emitter generates Go validation code from a *Node IR.
type emitter struct {
	buf        strings.Builder
	indent     int
	regexps    []regexpVar
	counter    int               // unique counter for variable names
	extraFuncs strings.Builder   // additional helper functions (e.g. additionalProperties validators)
	emittedAP  map[string]string // path -> function name for already-emitted AP validators
}

// nextID returns a unique integer for generating non-colliding variable names.
func (e *emitter) nextID() int {
	id := e.counter
	e.counter++
	return id
}

// line writes an indented line to the buffer.
func (e *emitter) line(format string, args ...any) {
	e.buf.WriteString(strings.Repeat("\t", e.indent))
	fmt.Fprintf(&e.buf, format, args...)
	e.buf.WriteByte('\n')
}

// blank writes a blank line.
func (e *emitter) blank() {
	e.buf.WriteByte('\n')
}

// push increases indentation.
func (e *emitter) push() { e.indent++ }

// pop decreases indentation.
func (e *emitter) pop() { e.indent-- }

// String returns the accumulated code.
func (e *emitter) String() string { return e.buf.String() + e.extraFuncs.String() }

// regexpVarName returns a stable variable name for a regexp pattern,
// registering it in e.regexps if not already present.
func (e *emitter) regexpVarName(pattern string) string {
	for _, rv := range e.regexps {
		if rv.Pattern == pattern {
			return rv.VarName
		}
	}
	name := fmt.Sprintf("_re%d", len(e.regexps))
	e.regexps = append(e.regexps, regexpVar{VarName: name, Pattern: pattern})
	return name
}

// EmitValidateFunc emits a complete top-level validation function for a
// mapping node. funcName is the exported Go function name; paramType is the
// Go type of the parameter (e.g. "workflow.WorkflowMapping"); node describes
// the schema constraints.
//
// The generated function signature is:
//
//	func <funcName>(m <paramType>) []rules.ValidationError
//
// The function body accesses m.MappingNode for the underlying *ast.MappingNode.
func (e *emitter) EmitValidateFunc(funcName string, paramType string, node *Node) {
	e.line("func %s(m %s) []rules.ValidationError {", funcName, paramType)
	e.push()
	e.line("var errs []rules.ValidationError")

	// Emit self checks (type/enum/if-then-else) on the mapping node itself.
	if len(node.Types) > 0 || len(node.Enum) > 0 || node.If != nil {
		e.blank()
		keyName := lastPathSegment(node.Path)
		e.emitValueChecks("ast.Node(m.MappingNode)", node, "errs", keyName)
	}

	e.blank()
	e.emitMappingBodyChecks("m.MappingNode", node, "errs")
	e.blank()
	e.line("return errs")
	e.pop()
	e.line("}")
}

// emitAPHelperFunc generates a helper function for validating additionalProperties
// values and returns the function name. The function signature is:
//
//	func <name>(value ast.Node, keyName string) []rules.ValidationError
//
// If a function for this path was already emitted, returns the existing name.
func (e *emitter) emitAPHelperFunc(node *Node) string {
	if e.emittedAP == nil {
		e.emittedAP = make(map[string]string)
	}
	if name, ok := e.emittedAP[node.Path]; ok {
		return name
	}

	id := e.nextID()
	funcName := fmt.Sprintf("_validateAP%d", id)
	e.emittedAP[node.Path] = funcName

	// Save current state and emit to extraFuncs buffer.
	origBuf := e.buf
	origIndent := e.indent
	e.buf = strings.Builder{}
	e.indent = 0

	e.blank()
	e.line("// %s validates additionalProperties values at path %q.", funcName, node.Path)
	e.line("func %s(value ast.Node, keyName string) []rules.ValidationError {", funcName)
	e.push()
	e.line("var errs []rules.ValidationError")
	e.emitValueChecks("value", node, "errs", "*", "keyName")
	e.line("return errs")
	e.pop()
	e.line("}")

	// Append to extraFuncs and restore state.
	e.extraFuncs.WriteString(e.buf.String())
	e.buf = origBuf
	e.indent = origIndent

	return funcName
}

// emitMappingBodyChecks emits unknown-key detection, required-key checks, and
// per-property checks for a mapping expression. It does NOT emit type/enum
// checks for the mapping node itself.
// parentKeyTokenExpr is an optional Go expression for the parent key's token,
// used to point required-key errors at the parent key instead of the mapping content.
func (e *emitter) emitMappingBodyChecks(mappingExpr string, node *Node, errsVar string, parentKeyTokenExpr ...string) {
	if node == nil {
		return
	}

	// Unknown key detection: when additionalProperties is explicitly false
	// and there are known properties or patternProperties.
	shouldCheckUnknown := node.AdditionalProperties != nil && !*node.AdditionalProperties &&
		(len(node.Properties) > 0 || len(node.PatternProps) > 0)

	if shouldCheckUnknown {
		knownKeys := make([]string, 0, len(node.Properties))
		for k := range node.Properties {
			knownKeys = append(knownKeys, k)
		}
		sort.Strings(knownKeys)

		e.line("// Unknown key detection")
		if len(knownKeys) > 0 {
			e.line("_knownKeys%s := map[string]bool{", sanitizeIdent(node.Path))
			e.push()
			for _, k := range knownKeys {
				e.line("%q: true,", k)
			}
			e.pop()
			e.line("}")
		}
		e.line("for _, _entry := range %s.Values {", mappingExpr)
		e.push()
		e.line("_key := _entry.Key.GetToken().Value")

		// Build the "known" condition: check against known properties and patternProperties.
		var knownConds []string
		if len(knownKeys) > 0 {
			knownConds = append(knownConds, fmt.Sprintf("_knownKeys%s[_key]", sanitizeIdent(node.Path)))
		}
		patternKeys := make([]string, 0, len(node.PatternProps))
		for p := range node.PatternProps {
			patternKeys = append(patternKeys, p)
		}
		sort.Strings(patternKeys)
		for _, pattern := range patternKeys {
			knownConds = append(knownConds, fmt.Sprintf("%s.MatchString(_key)", e.regexpVarName(pattern)))
		}
		e.line("if !(%s) {", strings.Join(knownConds, " || "))
		e.push()
		e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
		e.push()
		e.line("Kind:  rules.KindUnknownKey,")
		if node.Path != "" {
			e.line("Path:  %q,", node.Path)
		}
		if node.ParentName != "" {
			e.line("Parent: %q,", node.ParentName)
			e.line("Context: %q,", node.ContextTerm)
		} else if node.Path != "" {
			parts := strings.Split(node.Path, ".")
			lastPart := parts[len(parts)-1]
			// Skip wildcard segments from patternProperties — they produce
			// garbled messages like `"*" has unknown key "foo"`.
			if lastPart != "*" {
				e.line("Parent: %q,", lastPart)
			}
		}
		e.line("Key:   _key,")
		e.line("Token: _entry.Key.GetToken(),")
		e.pop()
		e.line("})")
		e.pop()
		e.line("}")
		e.pop()
		e.line("}")
		e.blank()
	}

	// Required key checks
	if len(node.Required) > 0 {
		wrapperVar := fmt.Sprintf("_mWrap%s", sanitizeIdent(node.Path))
		e.line("// Required key checks")
		e.line("%s := workflow.Mapping{MappingNode: %s}", wrapperVar, mappingExpr)
		// D1-D2: Use parent key token if available for better error positioning.
		tokenExpr := mappingExpr + ".GetToken()"
		if len(parentKeyTokenExpr) > 0 && parentKeyTokenExpr[0] != "" {
			tokenExpr = parentKeyTokenExpr[0]
		}
		for _, req := range node.Required {
			e.line("if %s.FindKey(%q) == nil {", wrapperVar, req)
			e.push()
			e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
			e.push()
			e.line("Kind:  rules.KindRequiredKey,")
			if node.Path != "" {
				e.line("Path:  %q,", node.Path)
			}
			e.line("Key:   %q,", req)
			e.line("Token: %s,", tokenExpr)
			e.pop()
			e.line("})")
			e.pop()
			e.line("}")
		}
		e.blank()
	}

	// V3: Property dependency checks
	if len(node.Dependencies) > 0 {
		depKeys := make([]string, 0, len(node.Dependencies))
		for k := range node.Dependencies {
			depKeys = append(depKeys, k)
		}
		sort.Strings(depKeys)

		depWrapperVar := fmt.Sprintf("_mDepWrap%s", sanitizeIdent(node.Path))
		e.line("// Property dependency checks")
		e.line("%s := workflow.Mapping{MappingNode: %s}", depWrapperVar, mappingExpr)
		for _, prop := range depKeys {
			reqd := node.Dependencies[prop]
			propIdent := sanitizeIdent(prop)
			e.line("if _depKV%s := %s.FindKey(%q); _depKV%s != nil {", propIdent, depWrapperVar, prop, propIdent)
			e.push()
			for _, req := range reqd {
				e.line("if %s.FindKey(%q) == nil {", depWrapperVar, req)
				e.push()
				e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
				e.push()
				e.line("Kind:  rules.KindDependency,")
				if node.Path != "" {
					e.line("Path:  %q,", node.Path)
				}
				e.line("Key:   %q,", prop)
				e.line("Got:   %q,", req)
				e.line("Token: _depKV%s.Key.GetToken(),", propIdent)
				e.pop()
				e.line("})")
				e.pop()
				e.line("}")
			}
			e.pop()
			e.line("}")
		}
		e.blank()
	}

	// Per-property value checks
	sortedProps := make([]string, 0, len(node.Properties))
	for k := range node.Properties {
		sortedProps = append(sortedProps, k)
	}
	sort.Strings(sortedProps)

	for _, key := range sortedProps {
		child := node.Properties[key]
		if child == nil {
			continue
		}
		if !nodeHasAnyChecks(child) {
			continue
		}

		varSuffix := sanitizeIdent(key)
		e.line("// Property: %q", key)
		e.line("if _kv%s := (workflow.Mapping{MappingNode: %s}).FindKey(%q); _kv%s != nil {", varSuffix, mappingExpr, key, varSuffix)
		e.push()
		e.emitValueChecks(fmt.Sprintf("_kv%s.Value", varSuffix), child, errsVar, key)
		e.pop()
		e.line("}")
		e.blank()
	}

	// PatternProperties: for each pattern, iterate mapping entries and validate
	// values whose keys match the pattern.
	if len(node.PatternProps) > 0 {
		sortedPatterns := make([]string, 0, len(node.PatternProps))
		for p := range node.PatternProps {
			sortedPatterns = append(sortedPatterns, p)
		}
		sort.Strings(sortedPatterns)

		for i, pattern := range sortedPatterns {
			child := node.PatternProps[pattern]
			regVar := e.regexpVarName(pattern)
			entryVar := fmt.Sprintf("_ppEntry%d", i)
			keyVar := fmt.Sprintf("_ppKey%d", i)
			e.line("// PatternProperty: %s", pattern)
			e.line("for _, %s := range %s.Values {", entryVar, mappingExpr)
			e.push()
			e.line("if %s.MatchString(%s.Key.GetToken().Value) {", regVar, entryVar)
			e.push()
			// Capture the actual YAML key name for use in error messages.
			e.line("%s := %s.Key.GetToken().Value", keyVar, entryVar)
			e.line("_ = %s // may be unused if no type checks in children", keyVar)
			e.emitValueChecks(fmt.Sprintf("%s.Value", entryVar), child, errsVar, "*", keyVar)
			e.pop()
			e.line("}")
			e.pop()
			e.line("}")
			e.blank()
		}
	}

	// G1: AdditionalProperties with schema — validate each mapping value.
	if node.AdditionalPropsSchema != nil {
		apNode := node.AdditionalPropsSchema
		funcName := e.emitAPHelperFunc(apNode)
		apEntryVar := "_apEntry"
		e.line("// AdditionalProperties schema validation (delegated to helper)")
		e.line("for _, %s := range %s.Values {", apEntryVar, mappingExpr)
		e.push()
		e.line("%s = append(%s, %s(%s.Value, %s.Key.GetToken().Value)...)", errsVar, errsVar, funcName, apEntryVar, apEntryVar)
		e.pop()
		e.line("}")
		e.blank()
	}

	// G4: MinProperties check
	if node.MinProperties > 0 {
		e.line("// minProperties check")
		e.line("if len(%s.Values) < %d {", mappingExpr, node.MinProperties)
		e.push()
		e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
		e.push()
		e.line("Kind:    rules.KindMinItems,")
		if node.Path != "" {
			e.line("Path:    %q,", node.Path)
		}
		e.line("Key:     %q,", lastPathSegment(node.Path))
		e.line("Got:     fmt.Sprintf(\"%%d\", len(%s.Values)),", mappingExpr)
		e.line("Allowed: []string{fmt.Sprintf(\"at least %%d\", %d)},", node.MinProperties)
		e.line("Token:   %s.GetToken(),", mappingExpr)
		e.pop()
		e.line("})")
		e.pop()
		e.line("}")
		e.blank()
	}
}

// nodeHasAnyChecks returns true if the node has any validation checks to emit.
func nodeHasAnyChecks(node *Node) bool {
	if node == nil {
		return false
	}
	return len(node.Types) > 0 || len(node.Enum) > 0 || node.Const != nil ||
		len(node.Properties) > 0 ||
		(node.AdditionalProperties != nil && !*node.AdditionalProperties) ||
		node.AdditionalPropsSchema != nil ||
		len(node.Required) > 0 || node.Items != nil || len(node.PatternProps) > 0 ||
		len(node.OneOf) > 0 || len(node.AllOf) > 0 || len(node.AnyOf) > 0 ||
		node.If != nil || node.Pattern != "" ||
		node.MinItems > 0 || node.MinProperties > 0 ||
		len(node.Dependencies) > 0
}

// emitValueChecks wraps all value checks in an expression bypass guard,
// then delegates to type, enum, and nested mapping checks.
// dynamicKeyExpr is an optional Go expression that provides the YAML key name at runtime
// (used for patternProperties where the key is dynamic, not static).
func (e *emitter) emitValueChecks(valueExpr string, node *Node, errsVar string, keyName string, dynamicKeyExpr ...string) {
	if node == nil {
		return
	}

	// Bypass all checks for GitHub Actions expression syntax (${{ ... }})
	e.line("if !rules.IsExpressionNode(%s) {", valueExpr)
	e.push()
	e.emitValueChecksOnExpr(valueExpr, node, errsVar, keyName, dynamicKeyExpr...)
	e.pop()
	e.line("}")
}

// emitValueChecksOnExpr emits type/enum/nested checks without the expression bypass wrapper.
func (e *emitter) emitValueChecksOnExpr(valueExpr string, node *Node, errsVar string, keyName string, dynamicKeyExpr ...string) {
	// When SkipChildren is set, only emit the type check and stop.
	// The child validation is handled by dedicated logic elsewhere.
	if node.SkipChildren {
		e.emitTypeCheck(valueExpr, node, errsVar, keyName, dynamicKeyExpr...)
		return
	}

	e.emitTypeCheck(valueExpr, node, errsVar, keyName, dynamicKeyExpr...)
	e.emitEnumCheck(valueExpr, node, errsVar, keyName)

	// G5: String pattern check
	if node.Pattern != "" {
		regVar := e.regexpVarName(node.Pattern)
		e.line("if _sv := rules.StringValue(%s); _sv != \"\" && !%s.MatchString(_sv) {", valueExpr, regVar)
		e.push()
		e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
		e.push()
		e.line("Kind:    rules.KindInvalidEnum,")
		if node.Path != "" {
			e.line("Path:    %q,", node.Path)
		}
		e.line("Key:     %q,", keyName)
		e.line("Got:     _sv,")
		e.line("Allowed: []string{%q},", node.Pattern)
		e.line("Token:   %s.GetToken(),", valueExpr)
		e.pop()
		e.line("})")
		e.pop()
		e.line("}")
	}

	// If this node represents a mapping with child constraints, recurse.
	if nodeHasChildMappingChecks(node) {
		e.line("if _subM%s, _ok%s := rules.UnwrapNode(%s).(*ast.MappingNode); _ok%s {", sanitizeIdent(keyName), sanitizeIdent(keyName), valueExpr, sanitizeIdent(keyName))
		e.push()
		// D1-D2: Pass parent key token for better required-error positioning.
		// If valueExpr looks like "_kvFoo.Value", derive "_kvFoo.Key.GetToken()".
		parentTokenExpr := ""
		if strings.HasSuffix(valueExpr, ".Value") {
			kvVar := strings.TrimSuffix(valueExpr, ".Value")
			parentTokenExpr = kvVar + ".Key.GetToken()"
		}
		e.emitMappingBodyChecks(fmt.Sprintf("_subM%s", sanitizeIdent(keyName)), node, errsVar, parentTokenExpr)
		e.pop()
		e.line("}")
	}

	// Sequence item validation
	if node.Items != nil {
		seqIdent := sanitizeIdent(keyName) + "Seq"
		e.line("if _%s, _%sOk := rules.UnwrapNode(%s).(*ast.SequenceNode); _%sOk {", seqIdent, seqIdent, valueExpr, seqIdent)
		e.push()
		// G4: MinItems check
		if node.MinItems > 0 {
			e.line("if len(_%s.Values) < %d {", seqIdent, node.MinItems)
			e.push()
			e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
			e.push()
			e.line("Kind:    rules.KindMinItems,")
			if node.Path != "" {
				e.line("Path:    %q,", node.Path)
			}
			e.line("Key:     %q,", keyName)
			e.line("Got:     fmt.Sprintf(\"%%d\", len(_%s.Values)),", seqIdent)
			e.line("Allowed: []string{fmt.Sprintf(\"at least %%d\", %d)},", node.MinItems)
			e.line("Token:   %s.GetToken(),", valueExpr)
			e.pop()
			e.line("})")
			e.pop()
			e.line("}")
		}
		e.line("for _, _item := range _%s.Values {", seqIdent)
		e.push()
		e.emitValueChecks("_item", node.Items, errsVar, keyName+"[]")
		e.pop()
		e.line("}")
		e.pop()
		e.line("}")
	}

	// oneOf validation
	if len(node.OneOf) > 0 {
		e.emitOneOf(valueExpr, node.OneOf, errsVar, keyName, dynamicKeyExpr...)
	}

	// allOf validation: validate against all sub-schemas
	if len(node.AllOf) > 0 {
		for _, branch := range node.AllOf {
			e.emitValueChecksOnExpr(valueExpr, branch, errsVar, keyName)
		}
	}

	// anyOf validation: same as allOf for our purposes (merge all constraints)
	if len(node.AnyOf) > 0 {
		e.emitAnyOf(valueExpr, node.AnyOf, errsVar, keyName)
	}

	// if/then/else validation
	if node.If != nil {
		e.emitIfThenElse(valueExpr, node, errsVar, keyName)
	}
}

// nodeHasChildMappingChecks returns true if the node has nested mapping constraints.
func nodeHasChildMappingChecks(node *Node) bool {
	if node == nil {
		return false
	}
	return (node.AdditionalProperties != nil && !*node.AdditionalProperties && len(node.Properties) > 0) ||
		len(node.Required) > 0 ||
		len(node.Properties) > 0 ||
		len(node.PatternProps) > 0 ||
		node.AdditionalPropsSchema != nil ||
		node.MinProperties > 0 ||
		len(node.Dependencies) > 0
}

// emitTypeCheck emits type assertion code for a value node.
// dynamicKeyExpr is an optional Go expression for the key name (used for patternProperties).
func (e *emitter) emitTypeCheck(valueExpr string, node *Node, errsVar string, keyName string, dynamicKeyExpr ...string) {
	if len(node.Types) == 0 {
		return
	}

	// Build the negated conditions: each is "!is<Type>(v)"
	var conditions []string
	for _, t := range node.Types {
		switch t {
		case "mapping":
			conditions = append(conditions, fmt.Sprintf("!rules.IsMapping(%s)", valueExpr))
		case "sequence":
			conditions = append(conditions, fmt.Sprintf("!rules.IsSequence(%s)", valueExpr))
		case "string":
			conditions = append(conditions, fmt.Sprintf("!rules.IsString(%s)", valueExpr))
		case "boolean":
			conditions = append(conditions, fmt.Sprintf("!rules.IsBoolean(%s)", valueExpr))
		case "integer":
			conditions = append(conditions, fmt.Sprintf("!rules.IsNumber(%s)", valueExpr))
		case "number":
			conditions = append(conditions, fmt.Sprintf("!rules.IsNumber(%s)", valueExpr))
		case "null":
			conditions = append(conditions, fmt.Sprintf("!rules.IsNull(%s)", valueExpr))
		}
	}

	if len(conditions) == 0 {
		return
	}

	// Fire error when ALL negations are true — i.e., none of the allowed types match.
	combined := strings.Join(conditions, " && ")
	// E3: Sort types in natural order (string > sequence > mapping > others)
	sortedTypes := naturalSortTypes(node.Types)
	allowedStrs := make([]string, len(sortedTypes))
	for i, t := range sortedTypes {
		allowedStrs[i] = fmt.Sprintf("%q", t)
	}

	e.line("if %s {", combined)
	e.push()
	e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
	e.push()
	e.line("Kind:    rules.KindTypeMismatch,")
	if node.Path != "" {
		e.line("Path:    %q,", node.Path)
	}
	// Use dynamic key expression if provided (for patternProperties).
	if len(dynamicKeyExpr) > 0 && dynamicKeyExpr[0] != "" {
		e.line("Key:     %s,", dynamicKeyExpr[0])
	} else {
		e.line("Key:     %q,", keyName)
	}
	e.line("Got:     rules.NodeTypeName(%s),", valueExpr)
	e.line("Allowed: []string{%s},", strings.Join(allowedStrs, ", "))
	e.line("Token:   %s.GetToken(),", valueExpr)
	e.pop()
	e.line("})")
	e.pop()
	e.line("}")
}

// emitEnumCheck emits enum validation code for a string value node.
func (e *emitter) emitEnumCheck(valueExpr string, node *Node, errsVar string, keyName string) {
	if len(node.Enum) == 0 {
		return
	}

	allowedStrs := make([]string, len(node.Enum))
	for i, v := range node.Enum {
		allowedStrs[i] = fmt.Sprintf("%q", v)
	}

	enumVarName := fmt.Sprintf("_validEnum%s", sanitizeIdent(keyName))
	e.line("if _sv := rules.StringValue(%s); _sv != \"\" {", valueExpr)
	e.push()
	e.line("%s := map[string]bool{", enumVarName)
	e.push()
	for _, v := range node.Enum {
		e.line("%q: true,", v)
	}
	e.pop()
	e.line("}")
	e.line("if !%s[_sv] {", enumVarName)
	e.push()
	e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
	e.push()
	e.line("Kind:    rules.KindInvalidEnum,")
	if node.Path != "" {
		e.line("Path:    %q,", node.Path)
	}
	if node.ParentName != "" {
		e.line("Parent:  %q,", node.ParentName)
		e.line("Context: %q,", node.ContextTerm)
	}
	e.line("Key:     %q,", keyName)
	e.line("Got:     _sv,")
	e.line("Allowed: []string{%s},", strings.Join(allowedStrs, ", "))
	e.line("Token:   %s.GetToken(),", valueExpr)
	e.pop()
	e.line("})")
	e.pop()
	e.line("}")
	e.pop()
	e.line("}")
}

// sanitizeIdent converts a key name into a valid Go identifier suffix.
// Hyphens, dots, and other non-alphanumeric characters are replaced with underscores.
func sanitizeIdent(key string) string {
	var sb strings.Builder
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// lastPathSegment returns the last dot-separated segment of a path.
// Returns the full string if there is no dot.
func lastPathSegment(path string) string {
	if path == "" {
		return ""
	}
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// oneOfClassification describes how to handle a oneOf.
type oneOfClassification int

const (
	oneOfTypeOnly       oneOfClassification = iota // all branches have only type constraints -> merge types
	oneOfTypeBranching                             // branches have different types with sub-constraints
	oneOfDiscrimEnum                               // discriminator key with different enum values per branch
	oneOfDiscrimPresent                            // discriminator key unique to each branch (presence-based)
	oneOfUnhandled                                 // too complex, skip
)

// classifyOneOf determines the oneOf pattern type.
func classifyOneOf(branches []*Node) oneOfClassification {
	if len(branches) == 0 {
		return oneOfUnhandled
	}

	// Check if all branches are type-only (no properties, no required, no enum, no items, no sub-combiners).
	allTypeOnly := true
	for _, b := range branches {
		if len(b.Properties) > 0 || len(b.Required) > 0 || len(b.Enum) > 0 ||
			b.Items != nil || len(b.PatternProps) > 0 ||
			len(b.OneOf) > 0 || len(b.AllOf) > 0 || len(b.AnyOf) > 0 ||
			b.If != nil || b.Const != nil || b.AdditionalPropsSchema != nil {
			allTypeOnly = false
			break
		}
	}
	if allTypeOnly {
		return oneOfTypeOnly
	}

	// Check for type-based branching: each branch has a distinct type.
	typeSet := map[string]bool{}
	allHaveType := true
	for _, b := range branches {
		if len(b.Types) == 0 {
			allHaveType = false
			break
		}
		for _, t := range b.Types {
			typeSet[t] = true
		}
	}
	if allHaveType && len(typeSet) >= len(branches) {
		return oneOfTypeBranching
	}

	// Check for discriminator-based: all branches are mapping-like with a shared key
	// that has different enum/const values per branch.
	if key, _ := findEnumDiscriminator(branches); key != "" {
		return oneOfDiscrimEnum
	}

	// Check for presence-based discriminator: branches have mutually exclusive required keys.
	if key := findPresenceDiscriminator(branches); key != "" {
		return oneOfDiscrimPresent
	}

	return oneOfUnhandled
}

// findEnumDiscriminator looks for a shared property key that has different
// enum or const values across branches. Returns the key and a map of
// enum values -> branch index.
func findEnumDiscriminator(branches []*Node) (string, map[string]int) {
	// Collect all property keys that appear in every branch.
	if len(branches) == 0 {
		return "", nil
	}

	// Find candidate keys: present in all branches with enum or const.
	candidates := map[string]bool{}
	for k := range branches[0].Properties {
		candidates[k] = true
	}
	for _, b := range branches[1:] {
		for k := range candidates {
			if _, ok := b.Properties[k]; !ok {
				delete(candidates, k)
			}
		}
	}

	for key := range candidates {
		// Check if each branch has enum or const on this key with no overlap.
		valueMap := map[string]int{}
		valid := true
		for i, b := range branches {
			prop := b.Properties[key]
			if prop == nil {
				valid = false
				break
			}
			vals := prop.Enum
			if prop.Const != nil {
				vals = []string{*prop.Const}
			}
			if len(vals) == 0 {
				valid = false
				break
			}
			for _, v := range vals {
				if _, exists := valueMap[v]; exists {
					valid = false
					break
				}
				valueMap[v] = i
			}
			if !valid {
				break
			}
		}
		if valid && len(valueMap) > 0 {
			return key, valueMap
		}
	}

	return "", nil
}

// findPresenceDiscriminator looks for a required key that is unique to each branch.
// Returns the key that can be used to discriminate, or "" if not found.
func findPresenceDiscriminator(branches []*Node) string {
	if len(branches) < 2 {
		return ""
	}

	// For each branch, find required keys not required in any other branch.
	for i, b := range branches {
		for _, req := range b.Required {
			unique := true
			for j, other := range branches {
				if i == j {
					continue
				}
				if slices.Contains(other.Required, req) {
					unique = false
				}
				if !unique {
					break
				}
			}
			if unique {
				return req
			}
		}
	}
	return ""
}

// flattenSingleAllOf normalizes oneOf branches: if a branch has no direct Types
// but has a single allOf child, merge the child's constraints into the branch.
// This handles patterns like push/pull_request where the schema uses
// oneOf: [null, { allOf: [object-with-properties, not{...}] }] and after G3
// filtering the allOf reduces to a single child whose types need promoting.
func flattenSingleAllOf(branches []*Node) {
	for _, b := range branches {
		if len(b.Types) == 0 && len(b.AllOf) == 1 {
			child := b.AllOf[0]
			if child == nil {
				b.AllOf = nil
				continue
			}
			// Precondition: since b.Types is empty, this branch is a pure allOf
			// wrapper with no direct constraints of its own. If a branch somehow
			// has both own constraints and an allOf child with constraints, that's
			// an unexpected schema shape — panic at generation time to avoid
			// silently dropping validation.
			b.Types = child.Types
			if len(b.Properties) == 0 {
				b.Properties = child.Properties
			} else if len(child.Properties) > 0 {
				panic(fmt.Sprintf("flattenSingleAllOf: branch %q has both direct and allOf Properties", b.Path))
			}
			if len(b.Required) == 0 {
				b.Required = child.Required
			} else if len(child.Required) > 0 {
				panic(fmt.Sprintf("flattenSingleAllOf: branch %q has both direct and allOf Required", b.Path))
			}
			if b.AdditionalProperties == nil {
				b.AdditionalProperties = child.AdditionalProperties
			}
			if b.AdditionalPropsSchema == nil {
				b.AdditionalPropsSchema = child.AdditionalPropsSchema
			}
			if len(b.PatternProps) == 0 {
				b.PatternProps = child.PatternProps
			} else if len(child.PatternProps) > 0 {
				panic(fmt.Sprintf("flattenSingleAllOf: branch %q has both direct and allOf PatternProps", b.Path))
			}
			if b.Items == nil {
				b.Items = child.Items
			}
			if b.MinItems == 0 {
				b.MinItems = child.MinItems
			}
			if b.MinProperties == 0 {
				b.MinProperties = child.MinProperties
			}
			if b.Pattern == "" {
				b.Pattern = child.Pattern
			}
			b.AllOf = nil
		}
	}
}

// emitOneOf emits validation code for a oneOf construct.
func (e *emitter) emitOneOf(valueExpr string, branches []*Node, errsVar string, keyName string, dynamicKeyExpr ...string) {
	flattenSingleAllOf(branches)
	classification := classifyOneOf(branches)

	switch classification {
	case oneOfTypeOnly:
		e.emitOneOfTypeOnly(valueExpr, branches, errsVar, keyName, dynamicKeyExpr...)
	case oneOfTypeBranching:
		e.emitOneOfTypeBranching(valueExpr, branches, errsVar, keyName, dynamicKeyExpr...)
	case oneOfDiscrimEnum:
		e.emitOneOfDiscrimEnum(valueExpr, branches, errsVar, keyName)
	case oneOfDiscrimPresent:
		e.emitOneOfDiscrimPresent(valueExpr, branches, errsVar, keyName, dynamicKeyExpr...)
	case oneOfUnhandled:
		// Skip — too complex to generate. Hand-written code can handle it.
		return
	}
}

// emitOneOfTypeOnly merges types from all branches and emits a single type check.
func (e *emitter) emitOneOfTypeOnly(valueExpr string, branches []*Node, errsVar string, keyName string, dynamicKeyExpr ...string) {
	// Collect all unique types from all branches.
	typeSet := map[string]bool{}
	for _, b := range branches {
		for _, t := range b.Types {
			typeSet[t] = true
		}
	}

	if len(typeSet) == 0 {
		return
	}

	// Build a synthetic node with merged types.
	merged := &Node{
		Path: branches[0].Path,
	}
	for t := range typeSet {
		merged.Types = append(merged.Types, t)
	}
	merged.Types = naturalSortTypes(merged.Types)

	e.emitTypeCheck(valueExpr, merged, errsVar, keyName, dynamicKeyExpr...)
}

// emitOneOfTypeBranching emits type-switching code for branches with different types.
func (e *emitter) emitOneOfTypeBranching(valueExpr string, branches []*Node, errsVar string, keyName string, dynamicKeyExpr ...string) {
	id := e.nextID()

	// Group branches by their primary type.
	// For type-based branching, emit: if isType1 { validate branch1 } else if isType2 { ... }
	first := true
	for _, b := range branches {
		if len(b.Types) == 0 {
			continue
		}

		// Build the type condition.
		var conditions []string
		for _, t := range b.Types {
			switch t {
			case "mapping":
				conditions = append(conditions, fmt.Sprintf("rules.IsMapping(%s)", valueExpr))
			case "sequence":
				conditions = append(conditions, fmt.Sprintf("rules.IsSequence(%s)", valueExpr))
			case "string":
				conditions = append(conditions, fmt.Sprintf("rules.IsString(%s)", valueExpr))
			case "boolean":
				conditions = append(conditions, fmt.Sprintf("rules.IsBoolean(%s)", valueExpr))
			case "integer", "number":
				conditions = append(conditions, fmt.Sprintf("rules.IsNumber(%s)", valueExpr))
			case "null":
				conditions = append(conditions, fmt.Sprintf("rules.IsNull(%s)", valueExpr))
			}
		}

		if len(conditions) == 0 {
			continue
		}

		cond := strings.Join(conditions, " || ")
		if first {
			e.line("// oneOf type branching (id=%d)", id)
			e.line("if %s {", cond)
			first = false
		} else {
			e.line("} else if %s {", cond)
		}
		e.push()

		// Emit sub-checks for this branch (excluding the type check itself since we already matched).
		e.emitEnumCheck(valueExpr, b, errsVar, keyName)
		if nodeHasChildMappingChecks(b) {
			subVar := fmt.Sprintf("_oneOfM%d", id)
			e.line("if %s, _ok := rules.UnwrapNode(%s).(*ast.MappingNode); _ok {", subVar, valueExpr)
			e.push()
			ptExpr := ""
			if strings.HasSuffix(valueExpr, ".Value") {
				ptExpr = strings.TrimSuffix(valueExpr, ".Value") + ".Key.GetToken()"
			}
			e.emitMappingBodyChecks(subVar, b, errsVar, ptExpr)
			e.pop()
			e.line("}")
		}
		if b.Items != nil {
			seqVar := fmt.Sprintf("_oneOfSeq%d", id)
			e.line("if %s, _ok := rules.UnwrapNode(%s).(*ast.SequenceNode); _ok {", seqVar, valueExpr)
			e.push()
			// MinItems check (same as emitValueChecksOnExpr)
			if b.MinItems > 0 {
				e.line("if len(%s.Values) < %d {", seqVar, b.MinItems)
				e.push()
				e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
				e.push()
				e.line("Kind:    rules.KindMinItems,")
				if b.Path != "" {
					e.line("Path:    %q,", b.Path)
				}
				e.line("Key:     %q,", keyName)
				e.line("Got:     fmt.Sprintf(\"%%d\", len(%s.Values)),", seqVar)
				e.line("Allowed: []string{fmt.Sprintf(\"at least %%d\", %d)},", b.MinItems)
				e.line("Token:   %s.GetToken(),", valueExpr)
				e.pop()
				e.line("})")
				e.pop()
				e.line("}")
			}
			e.line("for _, _item := range %s.Values {", seqVar)
			e.push()
			e.emitValueChecks("_item", b.Items, errsVar, keyName+"[]")
			e.pop()
			e.line("}")
			e.pop()
			e.line("}")
		}

		e.pop()
	}

	if !first {
		// Else branch: value doesn't match any oneOf type — emit type mismatch error.
		// Collect all expected types from the branches.
		allTypes := make([]string, 0)
		seen := make(map[string]bool)
		for _, b := range branches {
			for _, t := range b.Types {
				if !seen[t] {
					seen[t] = true
					allTypes = append(allTypes, t)
				}
			}
		}
		if len(allTypes) > 0 {
			allTypes = naturalSortTypes(allTypes)
			// Type mismatch (skip aliases — the anchor is validated)
			e.line("} else if !rules.IsAliasNode(%s) {", valueExpr)
			e.push()
			allowedSlice := fmt.Sprintf("[]string{%s}", joinQuoted(allTypes))
			e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
			e.push()
			e.line("Kind:    rules.KindTypeMismatch,")
			if keyName != "" && keyName != "*" {
				e.line("Path:    %q,", keyName)
				e.line("Key:     %q,", keyName)
			} else if len(dynamicKeyExpr) > 0 && dynamicKeyExpr[0] != "" {
				e.line("Key:     %s,", dynamicKeyExpr[0])
			}
			e.line("Got:     rules.NodeTypeName(%s),", valueExpr)
			e.line("Allowed: %s,", allowedSlice)
			e.line("Token:   %s.GetToken(),", valueExpr)
			e.pop()
			e.line("})")
			e.pop()
		}
		e.line("}")
	}
}

// emitOneOfDiscrimEnum emits discriminator-based branching using enum values on a shared key.
func (e *emitter) emitOneOfDiscrimEnum(valueExpr string, branches []*Node, errsVar string, keyName string) {
	discrimKey, valueMap := findEnumDiscriminator(branches)
	if discrimKey == "" {
		return
	}

	id := e.nextID()
	mappingVar := fmt.Sprintf("_oneOfDM%d", id)

	e.line("// oneOf discriminator on %q (id=%d)", discrimKey, id)
	e.line("if %s, _ok := rules.UnwrapNode(%s).(*ast.MappingNode); _ok {", mappingVar, valueExpr)
	e.push()

	discrimVar := fmt.Sprintf("_oneOfDV%d", id)
	e.line("if _kv := (workflow.Mapping{MappingNode: %s}).FindKey(%q); _kv != nil {", mappingVar, discrimKey)
	e.push()
	e.line("%s := rules.StringValue(_kv.Value)", discrimVar)
	// A4: If the discriminator value is not a string, emit a type mismatch error.
	e.line("if %s == \"\" && !rules.IsString(_kv.Value) {", discrimVar)
	e.push()
	e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
	e.push()
	e.line("Kind:    rules.KindTypeMismatch,")
	if keyName != "" && keyName != "*" {
		e.line("Path:    %q,", keyName)
	}
	e.line("Key:     %q,", discrimKey)
	e.line("Got:     rules.NodeTypeName(_kv.Value),")
	e.line("Allowed: []string{\"string\"},")
	e.line("Token:   _kv.Value.GetToken(),")
	e.pop()
	e.line("})")
	e.pop()
	e.line("} else {")
	e.push()

	// Group enum values by branch index.
	branchValues := make(map[int][]string)
	for val, idx := range valueMap {
		branchValues[idx] = append(branchValues[idx], val)
	}
	// Sort branch indices for determinism.
	branchIndices := make([]int, 0, len(branchValues))
	for idx := range branchValues {
		branchIndices = append(branchIndices, idx)
	}
	sort.Ints(branchIndices)

	first := true
	for _, idx := range branchIndices {
		vals := branchValues[idx]
		sort.Strings(vals)

		var conds []string
		for _, v := range vals {
			conds = append(conds, fmt.Sprintf("%s == %q", discrimVar, v))
		}
		cond := strings.Join(conds, " || ")

		if first {
			e.line("if %s {", cond)
			first = false
		} else {
			e.line("} else if %s {", cond)
		}
		e.push()

		branch := branches[idx]
		// Emit mapping body checks for this branch (required keys, properties, etc.)
		// D1-D2: Pass parent key token for better required-error positioning.
		parentTokenExpr := ""
		if strings.HasSuffix(valueExpr, ".Value") {
			kvVar := strings.TrimSuffix(valueExpr, ".Value")
			parentTokenExpr = kvVar + ".Key.GetToken()"
		}
		e.emitMappingBodyChecks(mappingVar, branch, errsVar, parentTokenExpr)

		e.pop()
	}
	if !first {
		// A3: else branch for unrecognized enum value
		allValues := make([]string, 0, len(valueMap))
		for val := range valueMap {
			allValues = append(allValues, val)
		}
		sort.Strings(allValues)
		e.line("} else {")
		e.push()
		e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
		e.push()
		e.line("Kind:    rules.KindInvalidEnum,")
		if keyName != "" && keyName != "*" {
			e.line("Path:    %q,", keyName)
		}
		e.line("Key:     %q,", discrimKey)
		e.line("Got:     %s,", discrimVar)
		e.line("Allowed: %s,", fmt.Sprintf("[]string{%s}", joinQuoted(allValues)))
		e.line("Token:   _kv.Value.GetToken(),")
		e.pop()
		e.line("})")
		e.pop()
		e.line("}")
	}

	e.pop()
	e.line("}") // close A4 string type check else
	e.pop()
	// A3: discriminator key absent → required error
	e.line("} else {")
	e.push()
	e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
	e.push()
	e.line("Kind:  rules.KindRequiredKey,")
	if keyName != "" && keyName != "*" {
		e.line("Path:  %q,", keyName)
	}
	e.line("Key:   %q,", discrimKey)
	e.line("Token: %s.GetToken(),", mappingVar)
	e.pop()
	e.line("})")
	e.pop()
	e.line("}")
	e.pop()
	// A4/A6: mapping cast failed → type mismatch (skip aliases — the anchor is validated)
	e.line("} else if !rules.IsAliasNode(%s) {", valueExpr)
	e.push()
	e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
	e.push()
	e.line("Kind:    rules.KindTypeMismatch,")
	if keyName != "" && keyName != "*" {
		e.line("Path:    %q,", keyName)
		e.line("Key:     %q,", keyName)
	}
	e.line("Got:     rules.NodeTypeName(%s),", valueExpr)
	e.line("Allowed: []string{\"mapping\"},")
	e.line("Token:   %s.GetToken(),", valueExpr)
	e.pop()
	e.line("})")
	e.pop()
	e.line("}")
}

// emitOneOfDiscrimPresent emits presence-based discriminator branching.
func (e *emitter) emitOneOfDiscrimPresent(valueExpr string, branches []*Node, errsVar string, keyName string, dynamicKeyExpr ...string) {
	id := e.nextID()
	mappingVar := fmt.Sprintf("_oneOfPM%d", id)

	e.line("// oneOf presence-based branching (id=%d)", id)
	e.line("if %s, _ok := rules.UnwrapNode(%s).(*ast.MappingNode); _ok {", mappingVar, valueExpr)
	e.push()

	wrapVar := fmt.Sprintf("_oneOfPW%d", id)
	e.line("%s := workflow.Mapping{MappingNode: %s}", wrapVar, mappingVar)

	first := true
	for _, b := range branches {
		// Find the unique required key for this branch.
		discrimKey := ""
		for _, req := range b.Required {
			unique := true
			for _, other := range branches {
				if other == b {
					continue
				}
				if slices.Contains(other.Required, req) {
					unique = false
				}
				if !unique {
					break
				}
			}
			if unique {
				discrimKey = req
				break
			}
		}
		if discrimKey == "" {
			continue
		}

		if first {
			e.line("if %s.FindKey(%q) != nil {", wrapVar, discrimKey)
			first = false
		} else {
			e.line("} else if %s.FindKey(%q) != nil {", wrapVar, discrimKey)
		}
		e.push()

		// D1-D2: Pass parent key token for better required-error positioning.
		parentTokenExpr := ""
		if strings.HasSuffix(valueExpr, ".Value") {
			kvVar := strings.TrimSuffix(valueExpr, ".Value")
			parentTokenExpr = kvVar + ".Key.GetToken()"
		}
		e.emitMappingBodyChecks(mappingVar, b, errsVar, parentTokenExpr)

		e.pop()
	}
	if !first {
		// Else branch: none of the discriminator keys are present.
		// Collect all discriminator keys to report which ones are required.
		var discrimKeys []string
		for _, b := range branches {
			for _, req := range b.Required {
				unique := true
				for _, other := range branches {
					if other == b {
						continue
					}
					if slices.Contains(other.Required, req) {
						unique = false
						break
					}
				}
				if unique {
					discrimKeys = append(discrimKeys, req)
					break
				}
			}
		}
		if len(discrimKeys) > 0 {
			sort.Strings(discrimKeys)
			// Report all discriminator keys as alternatives using Allowed field.
			e.line("} else {")
			e.push()
			e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
			e.push()
			e.line("Kind:  rules.KindRequiredKey,")
			// Always set Path from the first branch to enable proper token fixing.
			if len(branches) > 0 && branches[0].Path != "" {
				e.line("Path:  %q,", branches[0].Path)
			} else if keyName != "" && keyName != "*" {
				e.line("Path:  %q,", keyName)
			}
			e.line("Key:     %q,", discrimKeys[0])
			e.line("Allowed: []string{%s},", joinQuoted(discrimKeys))
			e.line("Token: %s.GetToken(),", mappingVar)
			e.pop()
			e.line("})")
			e.pop()
		}
		e.line("}")
	}

	e.pop()
	// Mapping cast failed → type mismatch (skip aliases — the anchor is validated)
	e.line("} else if !rules.IsAliasNode(%s) {", valueExpr)
	e.push()
	e.line("%s = append(%s, rules.ValidationError{", errsVar, errsVar)
	e.push()
	e.line("Kind:    rules.KindTypeMismatch,")
	if keyName != "" && keyName != "*" {
		e.line("Path:    %q,", keyName)
		e.line("Key:     %q,", keyName)
	} else if len(dynamicKeyExpr) > 0 && dynamicKeyExpr[0] != "" {
		e.line("Key:     %s,", dynamicKeyExpr[0])
	}
	e.line("Got:     rules.NodeTypeName(%s),", valueExpr)
	e.line("Allowed: []string{\"mapping\"},")
	e.line("Token:   %s.GetToken(),", valueExpr)
	e.pop()
	e.line("})")
	e.pop()
	e.line("}")
}

// emitAnyOf handles anyOf by merging types from all branches into a single type check.
// For GitHub Actions schemas, anyOf is typically used for "string or object" patterns.
func (e *emitter) emitAnyOf(valueExpr string, branches []*Node, errsVar string, keyName string) {
	// Collect all unique types from all branches.
	typeSet := map[string]bool{}
	for _, b := range branches {
		for _, t := range b.Types {
			typeSet[t] = true
		}
	}

	if len(typeSet) == 0 {
		return
	}

	merged := &Node{
		Path: branches[0].Path,
	}
	for t := range typeSet {
		merged.Types = append(merged.Types, t)
	}
	merged.Types = naturalSortTypes(merged.Types)

	e.emitTypeCheck(valueExpr, merged, errsVar, keyName)

	// For each branch that has sub-constraints, emit them guarded by type.
	for _, b := range branches {
		if nodeHasChildMappingChecks(b) {
			id := e.nextID()
			subVar := fmt.Sprintf("_anyOfM%d", id)
			e.line("if %s, _ok := rules.UnwrapNode(%s).(*ast.MappingNode); _ok {", subVar, valueExpr)
			e.push()
			ptExpr := ""
			if strings.HasSuffix(valueExpr, ".Value") {
				ptExpr = strings.TrimSuffix(valueExpr, ".Value") + ".Key.GetToken()"
			}
			e.emitMappingBodyChecks(subVar, b, errsVar, ptExpr)
			e.pop()
			e.line("}")
		}
		// G6: Also emit sequence items checks from anyOf branches.
		if b.Items != nil {
			id := e.nextID()
			seqVar := fmt.Sprintf("_anyOfSeq%d", id)
			e.line("if %s, _ok := rules.UnwrapNode(%s).(*ast.SequenceNode); _ok {", seqVar, valueExpr)
			e.push()
			e.line("for _, _item := range %s.Values {", seqVar)
			e.push()
			e.emitValueChecks("_item", b.Items, errsVar, keyName+"[]")
			e.pop()
			e.line("}")
			e.pop()
			e.line("}")
		}
	}
}

// emitIfThenElse emits conditional validation based on if/then/else schema.
func (e *emitter) emitIfThenElse(valueExpr string, node *Node, errsVar string, keyName string) {
	if node.If == nil {
		return
	}

	// We only handle the case where "if" checks a const/enum on a property.
	// This is the pattern used in GitHub Actions schemas (e.g., workflow_dispatch input type validation).
	condKey, condValue := extractIfCondition(node.If)
	if condKey == "" {
		// Too complex — skip.
		return
	}

	// Both then and else being nil means nothing to do.
	if node.Then == nil && node.Else == nil {
		return
	}

	id := e.nextID()
	mappingVar := fmt.Sprintf("_ifM%d", id)

	e.line("// if/then/else on %q == %q (id=%d)", condKey, condValue, id)
	e.line("if %s, _ok := rules.UnwrapNode(%s).(*ast.MappingNode); _ok {", mappingVar, valueExpr)
	e.push()

	condVar := fmt.Sprintf("_ifCV%d", id)
	// Handle nested key paths (e.g. "runs.using") by chaining FindKey calls.
	condKeyParts := strings.Split(condKey, ".")
	if len(condKeyParts) == 1 {
		e.line("if _kv := (workflow.Mapping{MappingNode: %s}).FindKey(%q); _kv != nil {", mappingVar, condKey)
		e.push()
		e.line("%s := rules.StringValue(_kv.Value)", condVar)
	} else {
		// Navigate to the nested key.
		currentMapping := mappingVar
		for i, part := range condKeyParts[:len(condKeyParts)-1] {
			nextVar := fmt.Sprintf("_ifNM%d_%d", id, i)
			e.line("if _kv := (workflow.Mapping{MappingNode: %s}).FindKey(%q); _kv != nil {", currentMapping, part)
			e.push()
			e.line("if %s, _ok := rules.UnwrapNode(_kv.Value).(*ast.MappingNode); _ok {", nextVar)
			e.push()
			currentMapping = nextVar
		}
		lastKey := condKeyParts[len(condKeyParts)-1]
		e.line("if _kv := (workflow.Mapping{MappingNode: %s}).FindKey(%q); _kv != nil {", currentMapping, lastKey)
		e.push()
		e.line("%s := rules.StringValue(_kv.Value)", condVar)
	}

	ptExpr := ""
	if strings.HasSuffix(valueExpr, ".Value") {
		ptExpr = strings.TrimSuffix(valueExpr, ".Value") + ".Key.GetToken()"
	}
	if node.Then != nil {
		e.line("if %s == %q {", condVar, condValue)
		e.push()
		e.emitMappingBodyChecks(mappingVar, node.Then, errsVar, ptExpr)
		e.pop()
		if node.Else != nil {
			e.line("} else {")
			e.push()
			e.emitMappingBodyChecks(mappingVar, node.Else, errsVar, ptExpr)
			e.pop()
		}
		e.line("}")
	} else if node.Else != nil {
		e.line("if %s != %q {", condVar, condValue)
		e.push()
		e.emitMappingBodyChecks(mappingVar, node.Else, errsVar, ptExpr)
		e.pop()
		e.line("}")
	}

	e.pop()
	e.line("}")
	// Close extra nesting for nested key paths.
	if len(condKeyParts) > 1 {
		for range (len(condKeyParts) - 1) * 2 {
			e.pop()
			e.line("}")
		}
	}

	e.pop()
	e.line("}")
}

// extractIfCondition extracts a condition from an "if" schema node.
// It handles shallow patterns: {"properties": {"key": {"const": "value"}}}
// and nested patterns: {"properties": {"a": {"properties": {"b": {"const": "value"}}}}}
// Returns the dot-separated key path and expected const value.
func extractIfCondition(ifNode *Node) (string, string) {
	if ifNode == nil || len(ifNode.Properties) == 0 {
		return "", ""
	}

	// Find a property with a const value (possibly nested).
	for key, prop := range ifNode.Properties {
		if prop == nil {
			continue
		}
		if prop.Const != nil {
			return key, *prop.Const
		}
		// Recurse into nested properties.
		if subKey, val := extractIfCondition(prop); subKey != "" {
			return key + "." + subKey, val
		}
	}

	return "", ""
}

// joinQuoted formats a string slice as Go code: `"a", "b", "c"`.
func joinQuoted(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(parts, ", ")
}

// naturalSortTypes sorts type names in a natural order for error messages:
// string, boolean, integer, number, null, sequence, mapping (scalar first, then compound).
func naturalSortTypes(types []string) []string {
	order := map[string]int{
		"string":   0,
		"boolean":  1,
		"integer":  2,
		"number":   3,
		"null":     4,
		"sequence": 5,
		"mapping":  6,
	}
	result := make([]string, len(types))
	copy(result, types)
	sort.Slice(result, func(i, j int) bool {
		oi, ok1 := order[result[i]]
		oj, ok2 := order[result[j]]
		if !ok1 {
			oi = 99
		}
		if !ok2 {
			oj = 99
		}
		return oi < oj
	})
	return result
}
