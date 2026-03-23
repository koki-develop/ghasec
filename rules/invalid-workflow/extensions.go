package invalidworkflow

import (
	"fmt"
	"slices"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/cron"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

// Hand-written validation extensions.
// These run AFTER generated validation and ADD errors — they never replace or skip
// generated validation. They cover validations that JSON Schema cannot express.

// B1: Filter conflicts — branches/branches-ignore, tags/tags-ignore, paths/paths-ignore.
func checkOnFilterConflicts(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil
	}
	onMapping, ok := rules.UnwrapNode(kv.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}
	var errs []*diagnostic.Error
	for _, entry := range onMapping.Values {
		eventMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: eventMapping}
		errs = append(errs, checkFilterConflict(m, "branches", "branches-ignore")...)
		errs = append(errs, checkFilterConflict(m, "tags", "tags-ignore")...)
		errs = append(errs, checkFilterConflict(m, "paths", "paths-ignore")...)
	}
	return errs
}

func checkFilterConflict(m workflow.Mapping, a, b string) []*diagnostic.Error {
	aKV := m.FindKey(a)
	bKV := m.FindKey(b)
	if aKV == nil || bKV == nil {
		return nil
	}
	firstToken := aKV.Key.GetToken()
	secondToken := bKV.Key.GetToken()
	if secondToken.Position.Offset < firstToken.Position.Offset {
		firstToken, secondToken = secondToken, firstToken
	}
	return []*diagnostic.Error{{
		Token:   firstToken,
		Message: fmt.Sprintf("%q and %q are mutually exclusive", a, b),
		Markers: []*token.Token{secondToken},
	}}
}

// checkJobExtensions runs hand-written checks on each job entry.
func checkJobExtensions(jobs *ast.MappingNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, jobEntry := range jobs.Values {
		jobMapping, ok := rules.UnwrapNode(jobEntry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: jobMapping}

		// B2: Job-level mutual exclusion
		errs = append(errs, checkJobMutualExclusion(jobEntry.Key.GetToken(), m)...)

		// Step validation
		if stepsKV := m.FindKey("steps"); stepsKV != nil {
			if seq, ok := rules.UnwrapNode(stepsKV.Value).(*ast.SequenceNode); ok {
				errs = append(errs, checkStepIDUniqueness(seq)...)
				errs = append(errs, checkStepExtensions(seq)...)
			}
		}
	}
	return errs
}

// B2: Job mutual exclusion — runs-on/uses, uses/steps.
func checkJobMutualExclusion(jobKey *token.Token, job workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	runsOnKV := job.FindKey("runs-on")
	usesKV := job.FindKey("uses")
	stepsKV := job.FindKey("steps")

	if runsOnKV != nil && usesKV != nil {
		firstToken := runsOnKV.Key.GetToken()
		secondToken := usesKV.Key.GetToken()
		if secondToken.Position.Offset < firstToken.Position.Offset {
			firstToken, secondToken = secondToken, firstToken
		}
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: "\"runs-on\" and \"uses\" are mutually exclusive",
			Markers: []*token.Token{firstToken, secondToken},
		})
	}
	if usesKV != nil && stepsKV != nil {
		firstToken := usesKV.Key.GetToken()
		secondToken := stepsKV.Key.GetToken()
		if secondToken.Position.Offset < firstToken.Position.Offset {
			firstToken, secondToken = secondToken, firstToken
		}
		errs = append(errs, &diagnostic.Error{
			Token:   jobKey,
			Message: "\"uses\" and \"steps\" are mutually exclusive",
			Markers: []*token.Token{firstToken, secondToken},
		})
	}
	return errs
}

// V1: Step ID uniqueness within a job.
func checkStepIDUniqueness(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	seen := make(map[string]*token.Token) // id value → first occurrence token
	for _, item := range seq.Values {
		stepMapping, ok := rules.UnwrapNode(item).(*ast.MappingNode)
		if !ok {
			continue
		}
		step := workflow.Mapping{MappingNode: stepMapping}
		idKV := step.FindKey("id")
		if idKV == nil {
			continue
		}
		idValue := rules.StringValue(idKV.Value)
		if idValue == "" || rules.IsExpressionNode(idKV.Value) {
			continue
		}
		if firstToken, exists := seen[idValue]; exists {
			errs = append(errs, &diagnostic.Error{
				Token:   idKV.Value.GetToken(),
				Message: fmt.Sprintf("step id %q must be unique", idValue),
				Markers: []*token.Token{firstToken},
			})
		} else {
			seen[idValue] = idKV.Value.GetToken()
		}
	}
	return errs
}

// checkStepExtensions runs hand-written checks on each step.
func checkStepExtensions(seq *ast.SequenceNode) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		stepMapping, ok := rules.UnwrapNode(item).(*ast.MappingNode)
		if !ok {
			continue
		}
		step := workflow.Mapping{MappingNode: stepMapping}

		// B3: Step mutual exclusion — uses/run
		usesKV := step.FindKey("uses")
		runKV := step.FindKey("run")
		if usesKV != nil && runKV != nil {
			firstToken := usesKV.Key.GetToken()
			secondToken := runKV.Key.GetToken()
			if secondToken.Position.Offset < firstToken.Position.Offset {
				firstToken, secondToken = secondToken, firstToken
			}
			errs = append(errs, &diagnostic.Error{
				Token:   firstToken,
				Message: "\"uses\" and \"run\" are mutually exclusive",
				Markers: []*token.Token{secondToken},
			})
		}

		// C1: Remote action ref format
		if usesKV != nil {
			stepW := workflow.StepMapping{Mapping: step}
			ref, ok := stepW.Uses()
			if ok && !ref.IsLocal() && !ref.IsDocker() && ref.Ref() == "" {
				errs = append(errs, &diagnostic.Error{
					Token:   ref.Token(),
					Message: fmt.Sprintf("%q must have a ref (e.g. %s@<ref>)", ref.String(), ref.String()),
				})
			}
		}
	}
	return errs
}

// V2: Needs reference validity and cycle detection.
func checkNeedsValidity(jobs *ast.MappingNode) []*diagnostic.Error {
	// Phase 1: Collect all job IDs and their document order.
	jobIDs := make(map[string]bool)
	var jobOrder []string // document order for deterministic cycle reporting
	for _, entry := range jobs.Values {
		id := entry.Key.GetToken().Value
		jobIDs[id] = true
		jobOrder = append(jobOrder, id)
	}

	var errs []*diagnostic.Error
	graph := make(map[string][]string) // jobID → dependency IDs (for cycle detection)

	for _, entry := range jobs.Values {
		jobID := entry.Key.GetToken().Value
		jobMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: jobMapping}
		needsKV := m.FindKey("needs")
		if needsKV == nil {
			continue
		}

		// needs can be a string or a sequence of strings
		needsValues := collectNeedsValues(needsKV.Value)
		for _, nv := range needsValues {
			if rules.IsExpressionNode(nv.node) {
				continue
			}
			if !jobIDs[nv.value] {
				errs = append(errs, &diagnostic.Error{
					Token:   nv.token,
					Message: fmt.Sprintf("job %q needs nonexistent job %q", jobID, nv.value),
				})
			} else {
				graph[jobID] = append(graph[jobID], nv.value)
			}
		}
	}

	// Phase 2: Cycle detection via DFS.
	errs = append(errs, detectCycles(jobs, graph, jobOrder)...)

	return errs
}

// needsValue holds a single needs reference with its source node and token.
type needsValue struct {
	value string
	token *token.Token
	node  ast.Node
}

// collectNeedsValues extracts needs references from a string or sequence node.
func collectNeedsValues(node ast.Node) []needsValue {
	node = rules.UnwrapNode(node)
	switch v := node.(type) {
	case *ast.StringNode:
		return []needsValue{{value: v.Value, token: v.GetToken(), node: v}}
	case *ast.LiteralNode:
		return []needsValue{{value: v.Value.Value, token: v.GetToken(), node: v}}
	case *ast.SequenceNode:
		var result []needsValue
		for _, item := range v.Values {
			item = rules.UnwrapNode(item)
			sv := rules.StringValue(item)
			if sv == "" {
				continue
			}
			result = append(result, needsValue{value: sv, token: item.GetToken(), node: item})
		}
		return result
	}
	return nil
}

// detectCycles runs DFS-based cycle detection on the needs dependency graph.
func detectCycles(jobs *ast.MappingNode, graph map[string][]string, jobOrder []string) []*diagnostic.Error {
	const (
		white = 0 // unvisited
		gray  = 1 // in current DFS path
		black = 2 // fully processed
	)

	color := make(map[string]int)
	parent := make(map[string]string) // tracks DFS path for cycle reconstruction

	var errs []*diagnostic.Error
	reportedCycles := make(map[string]bool) // avoid duplicate cycle reports

	var dfs func(node string)
	dfs = func(node string) {
		color[node] = gray
		for _, dep := range graph[node] {
			switch color[dep] {
			case gray:
				// Found a cycle: reconstruct path
				cycle := reconstructCycle(node, dep, parent)
				cycleKey := strings.Join(cycle, " -> ")
				if !reportedCycles[cycleKey] {
					reportedCycles[cycleKey] = true
					firstJob := firstInOrder(cycle, jobOrder)
					needsToken := findNeedsToken(jobs, firstJob)
					errs = append(errs, &diagnostic.Error{
						Token:   needsToken,
						Message: fmt.Sprintf("jobs must not have circular dependencies: %s", cycleKey),
					})
				}
			case white:
				parent[dep] = node
				dfs(dep)
			}
		}
		color[node] = black
	}

	// DFS in document order for deterministic results
	for _, jobID := range jobOrder {
		if color[jobID] == white {
			dfs(jobID)
		}
	}

	return errs
}

// reconstructCycle builds the cycle path from DFS back-edges.
func reconstructCycle(from, to string, parent map[string]string) []string {
	// Build path forward (from → ... → to), then reverse.
	var path []string
	current := from
	// Safety bound prevents infinite loop if parent map is ever inconsistent.
	for i := 0; current != to && i <= len(parent); i++ {
		path = append(path, current)
		current = parent[current]
	}
	path = append(path, to)
	slices.Reverse(path)
	path = append(path, to) // complete the cycle
	return path
}

// firstInOrder returns the first element from cycle that appears in jobOrder.
func firstInOrder(cycle, jobOrder []string) string {
	for _, j := range jobOrder {
		if slices.Contains(cycle, j) {
			return j
		}
	}
	return cycle[0]
}

// findNeedsToken returns the needs key token for a given job ID.
func findNeedsToken(jobs *ast.MappingNode, jobID string) *token.Token {
	for _, entry := range jobs.Values {
		if entry.Key.GetToken().Value == jobID {
			jobMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
			if !ok {
				return entry.Key.GetToken()
			}
			m := workflow.Mapping{MappingNode: jobMapping}
			if needsKV := m.FindKey("needs"); needsKV != nil {
				return needsKV.Key.GetToken()
			}
			return entry.Key.GetToken()
		}
	}
	return jobs.GetToken()
}

// V6: Cron expression syntax validation.
func checkCronExpressions(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil
	}
	onMapping, ok := rules.UnwrapNode(kv.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}
	m := workflow.Mapping{MappingNode: onMapping}
	scheduleKV := m.FindKey("schedule")
	if scheduleKV == nil {
		return nil
	}
	seq, ok := rules.UnwrapNode(scheduleKV.Value).(*ast.SequenceNode)
	if !ok {
		return nil
	}
	var errs []*diagnostic.Error
	for _, item := range seq.Values {
		entryMapping, ok := rules.UnwrapNode(item).(*ast.MappingNode)
		if !ok {
			continue
		}
		em := workflow.Mapping{MappingNode: entryMapping}
		cronKV := em.FindKey("cron")
		if cronKV == nil {
			continue
		}
		cronValue := rules.StringValue(cronKV.Value)
		if cronValue == "" || rules.IsExpressionNode(cronKV.Value) {
			continue
		}
		if errMsg := cron.Validate(cronValue); errMsg != "" {
			errs = append(errs, &diagnostic.Error{
				Token:   cronKV.Value.GetToken(),
				Message: fmt.Sprintf("invalid cron expression: %s", errMsg),
			})
		}
	}
	return errs
}

// V7: Choice default must be in options.
func checkChoiceDefaultInOptions(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil
	}
	onMapping, ok := rules.UnwrapNode(kv.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}
	onM := workflow.Mapping{MappingNode: onMapping}
	wdKV := onM.FindKey("workflow_dispatch")
	if wdKV == nil {
		return nil
	}
	wdMapping, ok := rules.UnwrapNode(wdKV.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}
	wdM := workflow.Mapping{MappingNode: wdMapping}
	inputsKV := wdM.FindKey("inputs")
	if inputsKV == nil {
		return nil
	}
	inputsMapping, ok := rules.UnwrapNode(inputsKV.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	for _, entry := range inputsMapping.Values {
		entryMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		m := workflow.Mapping{MappingNode: entryMapping}

		// Check type is "choice"
		typeKV := m.FindKey("type")
		if typeKV == nil {
			continue
		}
		typeValue := rules.StringValue(typeKV.Value)
		if typeValue != "choice" || rules.IsExpressionNode(typeKV.Value) {
			continue
		}

		// Get options
		optionsKV := m.FindKey("options")
		if optionsKV == nil {
			continue
		}
		optionsSeq, ok := rules.UnwrapNode(optionsKV.Value).(*ast.SequenceNode)
		if !ok {
			continue
		}
		optionSet := make(map[string]bool)
		var optionList []string
		for _, opt := range optionsSeq.Values {
			sv := rules.StringValue(opt)
			if sv != "" {
				optionSet[sv] = true
				optionList = append(optionList, sv)
			}
		}

		// Check default
		defaultKV := m.FindKey("default")
		if defaultKV == nil {
			continue
		}
		defaultValue := rules.StringValue(defaultKV.Value)
		if defaultValue == "" || rules.IsExpressionNode(defaultKV.Value) {
			continue
		}
		if !optionSet[defaultValue] {
			errs = append(errs, &diagnostic.Error{
				Token:   defaultKV.Value.GetToken(),
				Message: fmt.Sprintf("default value %q must be one of the options: %s", defaultValue, joinQuotedOptions(optionList)),
			})
		}
	}
	return errs
}

// joinQuotedOptions formats options as quoted alternatives: "a", "b", or "c".
func joinQuotedOptions(options []string) string {
	quoted := make([]string, len(options))
	for i, o := range options {
		quoted[i] = fmt.Sprintf("%q", o)
	}
	return rules.JoinOr(quoted)
}

// V9: Expression position validation — checks that expressions are not used in positions
// where GitHub Actions does not support them.
func checkExpressionPositions(mapping workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error

	// 1. Top-level defaults.run (job-level defaults.run IS valid)
	if defaultsKV := mapping.FindKey("defaults"); defaultsKV != nil {
		if defaultsMapping, ok := rules.UnwrapNode(defaultsKV.Value).(*ast.MappingNode); ok {
			dm := workflow.Mapping{MappingNode: defaultsMapping}
			if runKV := dm.FindKey("run"); runKV != nil {
				errs = append(errs, checkNodeNoExpressions(runKV, "\"run\"")...)
			}
		}
	}

	// 2. Permissions (top-level)
	if permKV := mapping.FindKey("permissions"); permKV != nil {
		errs = append(errs, checkNodeNoExpressions(permKV, "\"permissions\"")...)
	}

	// 3. on.* (all trigger config, with workflow_call exceptions)
	errs = append(errs, checkOnExpressionPositions(mapping)...)

	// Job-level checks
	if jobsKV := mapping.FindKey("jobs"); jobsKV != nil {
		if jobsMapping, ok := rules.UnwrapNode(jobsKV.Value).(*ast.MappingNode); ok {
			for _, jobEntry := range jobsMapping.Values {
				jobMapping, ok := rules.UnwrapNode(jobEntry.Value).(*ast.MappingNode)
				if !ok {
					continue
				}
				jm := workflow.Mapping{MappingNode: jobMapping}

				// 2. Permissions (job-level)
				if permKV := jm.FindKey("permissions"); permKV != nil {
					errs = append(errs, checkNodeNoExpressions(permKV, "\"permissions\"")...)
				}

				// 4. jobs.*.needs
				if needsKV := jm.FindKey("needs"); needsKV != nil {
					errs = append(errs, checkNodeNoExpressions(needsKV, "\"needs\"")...)
				}

				// 5. jobs.*.uses (reusable workflow call)
				if usesKV := jm.FindKey("uses"); usesKV != nil {
					errs = append(errs, checkValueNoExpressions(usesKV.Value, "\"uses\"")...)
				}

				// Step-level checks
				if stepsKV := jm.FindKey("steps"); stepsKV != nil {
					if seq, ok := rules.UnwrapNode(stepsKV.Value).(*ast.SequenceNode); ok {
						for _, item := range seq.Values {
							stepMapping, ok := rules.UnwrapNode(item).(*ast.MappingNode)
							if !ok {
								continue
							}
							sm := workflow.Mapping{MappingNode: stepMapping}

							// 6. steps[].id
							if idKV := sm.FindKey("id"); idKV != nil {
								errs = append(errs, checkValueNoExpressions(idKV.Value, "\"id\"")...)
							}

							// 7. steps[].uses
							if usesKV := sm.FindKey("uses"); usesKV != nil {
								errs = append(errs, checkValueNoExpressions(usesKV.Value, "\"uses\"")...)
							}
						}
					}
				}
			}
		}
	}

	return errs
}

// checkNodeNoExpressions checks a single key-value pair for expressions.
// It recurses into the value side (sequences, mappings).
func checkNodeNoExpressions(kv *ast.MappingValueNode, keyPath string) []*diagnostic.Error {
	return checkValueNoExpressions(kv.Value, keyPath)
}

// checkValueNoExpressions checks a value node for expressions, recursing into
// sequences and mappings.
func checkValueNoExpressions(node ast.Node, keyPath string) []*diagnostic.Error {
	node = rules.UnwrapNode(node)
	switch v := node.(type) {
	case *ast.SequenceNode:
		var errs []*diagnostic.Error
		for _, item := range v.Values {
			errs = append(errs, checkValueNoExpressions(item, keyPath)...)
		}
		return errs
	case *ast.MappingNode:
		return checkMappingNoExpressions(workflow.Mapping{MappingNode: v})
	default:
		spanTokens := rules.ExpressionSpanTokens(node)
		if len(spanTokens) == 0 {
			return nil
		}
		var errs []*diagnostic.Error
		for _, st := range spanTokens {
			errs = append(errs, &diagnostic.Error{
				Token:   st,
				Message: fmt.Sprintf("%s must not contain expressions", keyPath),
			})
		}
		return errs
	}
}

// checkMappingNoExpressions checks all values in a mapping for expressions.
// Each entry uses its own key name as the keyPath for more specific error messages.
func checkMappingNoExpressions(m workflow.Mapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, entry := range m.Values {
		key := entry.Key.GetToken().Value
		errs = append(errs, checkValueNoExpressions(entry.Value, fmt.Sprintf("%q", key))...)
	}
	return errs
}

// checkOnExpressionPositions handles the "on" trigger config, with exceptions
// for workflow_call.inputs[].default and workflow_call.outputs[].value.
func checkOnExpressionPositions(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil
	}

	// "on" can be a string, sequence, or mapping
	onNode := rules.UnwrapNode(kv.Value)
	switch v := onNode.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		var errs []*diagnostic.Error
		for _, st := range rules.ExpressionSpanTokens(onNode) {
			errs = append(errs, &diagnostic.Error{
				Token:   st,
				Message: "\"on\" must not contain expressions",
			})
		}
		return errs
	case *ast.SequenceNode:
		var errs []*diagnostic.Error
		for _, item := range v.Values {
			for _, st := range rules.ExpressionSpanTokens(item) {
				errs = append(errs, &diagnostic.Error{
					Token:   st,
					Message: "\"on\" must not contain expressions",
				})
			}
		}
		return errs
	case *ast.MappingNode:
		var errs []*diagnostic.Error
		for _, entry := range v.Values {
			eventName := entry.Key.GetToken().Value
			if eventName == "workflow_call" {
				errs = append(errs, checkWorkflowCallExpressionPositions(entry.Value)...)
				continue
			}
			errs = append(errs, checkValueNoExpressions(entry.Value, fmt.Sprintf("%q", eventName))...)
		}
		return errs
	}
	return nil
}

// checkWorkflowCallExpressionPositions handles workflow_call, skipping
// inputs[].default and outputs[].value which ARE valid expression positions.
func checkWorkflowCallExpressionPositions(node ast.Node) []*diagnostic.Error {
	node = rules.UnwrapNode(node)
	wcMapping, ok := node.(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error

	for _, entry := range wcMapping.Values {
		sectionName := entry.Key.GetToken().Value

		switch sectionName {
		case "inputs":
			inputsMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
			if !ok {
				continue
			}
			for _, inputEntry := range inputsMapping.Values {
				inputDefMapping, ok := rules.UnwrapNode(inputEntry.Value).(*ast.MappingNode)
				if !ok {
					continue
				}
				for _, field := range inputDefMapping.Values {
					fieldName := field.Key.GetToken().Value
					if fieldName == "default" {
						// inputs[].default IS valid — skip
						continue
					}
					errs = append(errs, checkValueNoExpressions(field.Value, fmt.Sprintf("%q", fieldName))...)
				}
			}
		case "outputs":
			outputsMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
			if !ok {
				continue
			}
			for _, outputEntry := range outputsMapping.Values {
				outputDefMapping, ok := rules.UnwrapNode(outputEntry.Value).(*ast.MappingNode)
				if !ok {
					continue
				}
				for _, field := range outputDefMapping.Values {
					fieldName := field.Key.GetToken().Value
					if fieldName == "value" {
						// outputs[].value IS valid — skip
						continue
					}
					errs = append(errs, checkValueNoExpressions(field.Value, fmt.Sprintf("%q", fieldName))...)
				}
			}
		default:
			// secrets, other keys — no expressions allowed
			errs = append(errs, checkValueNoExpressions(entry.Value, fmt.Sprintf("%q", sectionName))...)
		}
	}
	return errs
}

// V8: Filter negation requires at least one positive pattern.
func checkFilterNegationPatterns(mapping workflow.Mapping) []*diagnostic.Error {
	kv := mapping.FindKey("on")
	if kv == nil {
		return nil
	}
	onMapping, ok := rules.UnwrapNode(kv.Value).(*ast.MappingNode)
	if !ok {
		return nil
	}

	var errs []*diagnostic.Error
	targetEvents := []string{"push", "pull_request", "pull_request_target"}
	filterKeys := []string{"branches", "tags", "paths"}

	for _, entry := range onMapping.Values {
		eventName := entry.Key.GetToken().Value
		if !slices.Contains(targetEvents, eventName) {
			continue
		}

		eventMapping, ok := rules.UnwrapNode(entry.Value).(*ast.MappingNode)
		if !ok {
			continue
		}
		em := workflow.Mapping{MappingNode: eventMapping}

		for _, filterKey := range filterKeys {
			filterKV := em.FindKey(filterKey)
			if filterKV == nil {
				continue
			}
			seq, ok := rules.UnwrapNode(filterKV.Value).(*ast.SequenceNode)
			if !ok {
				continue
			}

			hasNegative := false
			hasPositive := false
			for _, item := range seq.Values {
				sv := rules.StringValue(item)
				if sv == "" {
					continue
				}
				if strings.HasPrefix(sv, "!") {
					hasNegative = true
				} else {
					hasPositive = true
				}
			}
			if hasNegative && !hasPositive {
				errs = append(errs, &diagnostic.Error{
					Token:   filterKV.Key.GetToken(),
					Message: fmt.Sprintf("if a %q pattern starts with \"!\", at least one positive pattern is also required", filterKey),
				})
			}
		}
	}
	return errs
}
