package invalidworkflow

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "invalid-workflow"

type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return true }
func (r *Rule) Online() bool   { return false }

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	// Generated schema validation (covers: top-level unknown/required keys,
	// on validation, permissions, concurrency, defaults type/key checks).
	fileStart := mapping.FirstToken()
	genErrs := rules.Dedup(validateWorkflow(mapping))
	// Fix error tokens BEFORE sorting
	for i := range genErrs {
		// Top-level required errors should point to file start
		if genErrs[i].Kind == rules.KindRequiredKey && genErrs[i].Path == "" {
			genErrs[i].Token = fileStart
		}
		// Nested required errors should point to the parent key, not the mapping content.
		// e.g. concurrency.group required → point to "concurrency:" key
		if genErrs[i].Kind == rules.KindRequiredKey && genErrs[i].Path != "" {
			parentKey := strings.Split(genErrs[i].Path, ".")[0]
			if kv := mapping.FindKey(parentKey); kv != nil {
				genErrs[i].Token = kv.Key.GetToken()
			}
		}
	}
	for _, ve := range rules.SortRequiredFirst(genErrs) {
		if isHandWrittenPath(ve.Path) {
			continue
		}
		errs = append(errs, toDiagnostic(ve))
	}

	// Hand-written checks NOT covered by generated validator:

	// on: type mismatch fallback (generated has no else clause for oneOf)
	errs = append(errs, checkOnTypeFallback(mapping.Mapping)...)

	// on: filter conflicts (branches/branches-ignore etc.) — uses Markers
	errs = append(errs, checkOnFilterConflicts(mapping.Mapping)...)

	// on: schedule and workflow_dispatch deep validation (generated code doesn't descend far enough)
	if onKV := mapping.FindKey("on"); onKV != nil {
		if onMapping, ok := onKV.Value.(*ast.MappingNode); ok {
			for _, eventEntry := range onMapping.Values {
				eventName := eventEntry.Key.GetToken().Value
				switch eventName {
				case "schedule":
					errs = append(errs, checkOnSchedule(eventEntry)...)
				case "workflow_dispatch":
					errs = append(errs, checkOnWorkflowDispatch(eventEntry)...)
				}
			}
		}
	}

	// concurrency: type fallback for types not handled by generated oneOf (e.g. integer)
	if kv := mapping.FindKey("concurrency"); kv != nil {
		errs = append(errs, checkConcurrencyTypeFallback(kv)...)
	}

	// permissions: type mismatch fallback + null handling
	if kv := mapping.FindKey("permissions"); kv != nil {
		errs = append(errs, checkPermissionsTypeFallback(kv)...)
	}

	// jobs: null/empty check + entry validation (required check handled by generated code)
	if kv := mapping.FindKey("jobs"); kv != nil {
		if _, ok := kv.Value.(*ast.NullNode); ok {
			errs = append(errs, &diagnostic.Error{
				Token:   kv.Key.GetToken(),
				Message: "\"jobs\" must not be empty",
			})
		} else if jobsMapping, ok := kv.Value.(*ast.MappingNode); ok {
			errs = append(errs, checkJobEntries(jobsMapping)...)
		} else if !isExpression(kv.Value) {
			errs = append(errs, &diagnostic.Error{
				Token:   kv.Value.GetToken(),
				Message: fmt.Sprintf("\"jobs\" must be a mapping, but got %s", rules.NodeTypeName(kv.Value)),
			})
		}
	}

	return errs
}

// toDiagnostic converts a generated ValidationError to a diagnostic.Error,
// producing messages that match the hand-written format.
func toDiagnostic(ve rules.ValidationError) *diagnostic.Error {
	var msg string
	switch ve.Kind {
	case rules.KindUnknownKey:
		if ve.Parent != "" && ve.Context != "" {
			msg = fmt.Sprintf("%q has unknown %s %q", ve.Parent, ve.Context, ve.Key)
		} else if ve.Parent != "" {
			msg = fmt.Sprintf("%q has unknown key %q", ve.Parent, ve.Key)
		} else {
			msg = fmt.Sprintf("unknown key %q", ve.Key)
		}
	case rules.KindRequiredKey:
		msg = fmt.Sprintf("%q is required", ve.Key)
	case rules.KindTypeMismatch:
		if before, ok := strings.CutSuffix(ve.Key, "[]"); ok {
			base := before
			msg = fmt.Sprintf("%q elements must be %s, but got %s", base, joinPlural(ve.Allowed), ve.Got)
		} else if strings.HasPrefix(ve.Path, "permissions.") && ve.Path != "permissions" {
			// Permission scope type mismatch
			msg = fmt.Sprintf("\"permissions\" scope %q must be a %s, but got %s", ve.Key, strings.Join(ve.Allowed, " or "), ve.Got)
		} else {
			msg = fmt.Sprintf("%q must be a %s, but got %s", ve.Key, strings.Join(ve.Allowed, " or "), ve.Got)
		}
	case rules.KindInvalidEnum:
		if ve.Parent == "on" && ve.Context == "event" {
			msg = fmt.Sprintf("\"on\" has unknown event %q", ve.Got)
		} else if strings.HasPrefix(ve.Path, "on.") || strings.HasPrefix(ve.Path, "on*") {
			// Enum error within on sequence items
			msg = fmt.Sprintf("\"on\" has unknown event %q", ve.Got)
		} else if strings.HasPrefix(ve.Path, "permissions.") {
			// Permission scope level: "permissions" scope "<key>" must be "read", "write", or "none", but got "<value>"
			msg = fmt.Sprintf("\"permissions\" scope %q must be %s, but got %q", ve.Key, joinQuoted(ve.Allowed), ve.Got)
		} else if ve.Path == "permissions" && ve.Key == "permissions" {
			// Top-level permissions string: "permissions" must be "read-all" or "write-all", but got "<value>"
			msg = fmt.Sprintf("\"permissions\" must be %s, but got %q", joinQuoted(ve.Allowed), ve.Got)
		} else if ve.Parent != "" && ve.Context != "" {
			msg = fmt.Sprintf("%q has unknown %s %q", ve.Parent, ve.Context, ve.Got)
		} else {
			msg = fmt.Sprintf("%q has unknown value %q", ve.Key, ve.Got)
		}
	default:
		msg = fmt.Sprintf("validation error on %q: %s", ve.Key, ve.Got)
	}
	return &diagnostic.Error{Token: ve.Token, Message: msg}
}

// joinQuoted formats allowed values as quoted alternatives: "a", "b", or "c".
func joinQuoted(allowed []string) string {
	if len(allowed) == 0 {
		return "(none)"
	}
	quoted := make([]string, len(allowed))
	for i, a := range allowed {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	if len(quoted) <= 2 {
		return strings.Join(quoted, " or ")
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + ", or " + quoted[len(quoted)-1]
}

// joinPlural formats allowed types in plural form: "strings", "mappings", etc.
func joinPlural(allowed []string) string {
	if len(allowed) == 0 {
		return "(none)"
	}
	plural := make([]string, len(allowed))
	for i, a := range allowed {
		plural[i] = a + "s"
	}
	if len(plural) <= 2 {
		return strings.Join(plural, " or ")
	}
	return strings.Join(plural[:len(plural)-1], ", ") + ", or " + plural[len(plural)-1]
}

// isHandWrittenPath returns true if errors at this path are handled by
// hand-written checks (schedule, workflow_dispatch deep validation, jobs).
func isHandWrittenPath(path string) bool {
	// schedule and workflow_dispatch have complex validation that hand-written code
	// handles better (cron required, input key validation, etc.)
	if strings.HasPrefix(path, "on.schedule") {
		return true
	}
	if strings.HasPrefix(path, "on.workflow_dispatch") {
		return true
	}
	// Job-level validation is still hand-written
	if path == "jobs" || strings.HasPrefix(path, "jobs.") {
		return true
	}
	return false
}

// checkOnTypeFallback catches the case where "on" has a type not handled by
// the generated oneOf branches (e.g. on: 123).
func checkOnTypeFallback(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil // required check handled by generated code
	}
	if isExpression(kv.Value) {
		return nil
	}
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode, *ast.SequenceNode, *ast.MappingNode:
		return nil // handled by generated code
	default:
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"on\" must be a string, sequence, or mapping, but got %s", rules.NodeTypeName(kv.Value)),
		}}
	}
}

// checkOnFilterConflicts checks for mutually exclusive filter keys in on events.
func checkOnFilterConflicts(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil
	}
	onMapping, ok := kv.Value.(*ast.MappingNode)
	if !ok {
		return nil
	}
	var errs []*diagnostic.Error
	for _, entry := range onMapping.Values {
		eventName := entry.Key.GetToken().Value
		if !knownOnEvents[eventName] {
			continue
		}
		if eventName == "schedule" || eventName == "workflow_dispatch" {
			continue
		}
		errs = append(errs, checkOnEventFilters(entry)...)
	}
	return errs
}

// checkConcurrencyTypeFallback catches concurrency values that are not
// string or mapping (not handled by generated oneOf).
func checkConcurrencyTypeFallback(kv *ast.MappingValueNode) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode, *ast.MappingNode:
		return nil // handled by generated code
	default:
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"concurrency\" must be a string or mapping, but got %s", rules.NodeTypeName(kv.Value)),
		}}
	}
}

// checkPermissionsTypeFallback catches permissions values that are not
// string, mapping, or null (not handled by generated oneOf).
func checkPermissionsTypeFallback(kv *ast.MappingValueNode) []*diagnostic.Error {
	if isExpression(kv.Value) {
		return nil
	}
	switch kv.Value.(type) {
	case *ast.StringNode, *ast.LiteralNode, *ast.MappingNode, *ast.NullNode:
		return nil // handled by generated code or intentionally allowed
	default:
		return []*diagnostic.Error{{
			Token:   kv.Value.GetToken(),
			Message: fmt.Sprintf("\"permissions\" must be a string or mapping, but got %s", rules.NodeTypeName(kv.Value)),
		}}
	}
}
