// Package shellcheck implements a ghasec rule that runs shellcheck against the
// shell scripts embedded in run: steps and reports its findings as ghasec
// diagnostics.
//
// GitHub Actions expressions (${{ ... }}) are masked with byte-length-preserving
// uppercase variable placeholders before analysis (see mask.go), and findings
// that fall entirely within those placeholders are dropped, so no shellcheck
// code needs to be excluded by name. Findings are mapped back to precise YAML
// positions (see position.go). Each finding is reported with RuleID
// "shellcheck/SC<code>" linking to the shellcheck wiki.
package shellcheck

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "shellcheck"

// execSem bounds the number of concurrent shellcheck subprocesses across the
// whole process. Each run step spawns one shellcheck invocation; without a
// global cap, parallelizing per-step (on top of file-level concurrency) could
// fork hundreds of processes at once and thrash the scheduler. Sizing it to the
// CPU count keeps the cores busy without oversubscription.
var execSem = make(chan struct{}, max(runtime.NumCPU()*2, 1))

// Rule runs shellcheck against run: steps. It implements both WorkflowRule and
// ActionRule. All methods use pointer receivers because the rule carries a
// shared atomic flag and must not be copied.
type Rule struct {
	Runner Runner

	// sawEligibleStep records whether at least one shell run step was found that
	// would have been analyzed had the shellcheck binary been available. cmd/root
	// uses it to decide whether to show the "install shellcheck" hint. Accessed
	// concurrently across files/jobs, hence atomic.
	sawEligibleStep atomic.Bool

	// cache holds precomputed diagnostics keyed by the run-value AST node,
	// populated by Precompute. When precomputed is set, CheckWorkflow/CheckAction
	// serve results from it instead of invoking shellcheck per file. This lets
	// cmd/root batch every run step across all files into a few shellcheck
	// invocations, paying the (dominant) process-startup cost a handful of times
	// rather than once per file. A sync.Map is used because Precompute may run for
	// the workflow and action batches concurrently (they write disjoint keys)
	// while analysis reads it. When precomputed is unset (no Precompute call, e.g.
	// unit tests), the per-file path is used as a fallback.
	cache       sync.Map // map[ast.Node][]*diagnostic.Error
	precomputed atomic.Bool
	// ready is closed by MarkReady once every precompute batch has populated the
	// cache. resultsFor (cache path) blocks on it, so analysis can begin — and run
	// its many non-shellcheck rules — concurrently with the (slow) shellcheck
	// precompute: only the shellcheck rule waits, the rest overlap. Set up by
	// BeginPrecompute before analysis starts.
	ready chan struct{}
}

// BeginPrecompute marks the rule as serving from the precompute cache and arms
// the readiness gate. It must be called before any concurrent analysis and
// before the precompute batches run, so resultsFor takes the cache path (and
// waits for readiness) rather than the per-file fallback.
func (r *Rule) BeginPrecompute() {
	r.ready = make(chan struct{})
	r.precomputed.Store(true)
}

// MarkReady signals that all precompute batches have finished populating the
// cache, unblocking analysis reads. It must be called exactly once after the
// last Precompute call.
func (r *Rule) MarkReady() { close(r.ready) }

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

// SawEligibleStep reports whether an analyzable shell run step was encountered
// while the shellcheck binary was unavailable.
func (r *Rule) SawEligibleStep() bool { return r.sawEligibleStep.Load() }

// shellStep pairs an analyzable run step with its resolved shell.
type shellStep struct {
	step  workflow.StepMapping
	shell string
}

// collectWorkflowSteps returns the analyzable shell run steps of a workflow,
// each paired with its resolved shellcheck dialect.
func collectWorkflowSteps(mapping workflow.WorkflowMapping) []shellStep {
	wfShell, wfOK := mapping.DefaultsRunShell()

	var steps []shellStep
	mapping.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		jobShell, jobOK := job.DefaultsRunShell()
		runsOn := job.RunsOnNode()
		job.EachStep(func(step workflow.StepMapping) {
			effShell, specified := resolveEffectiveShell(step, jobShell, jobOK, wfShell, wfOK)
			sh, target := resolveWorkflowTarget(effShell, specified, runsOn)
			if !target {
				return
			}
			steps = append(steps, shellStep{step: step, shell: sh})
		})
	})
	return steps
}

// collectActionSteps returns the analyzable shell run steps of a composite
// action, each paired with its resolved shellcheck dialect.
func collectActionSteps(mapping workflow.ActionMapping) []shellStep {
	var steps []shellStep
	mapping.EachStep(func(step workflow.StepMapping) {
		// Composite action run steps require an explicit shell (its absence is
		// reported by invalid-action). No runs-on / defaults exist here, so there
		// is no bash fallback: an unspecified or non-bash/sh shell is skipped.
		shellKV := step.FindKey("shell")
		if shellKV == nil {
			return
		}
		sh, ok := normalizeShell(rules.StringValue(shellKV.Value))
		if !ok {
			return
		}
		steps = append(steps, shellStep{step: step, shell: sh})
	})
	return steps
}

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	return r.resultsFor(collectWorkflowSteps(mapping))
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	return r.resultsFor(collectActionSteps(mapping))
}

// resultsFor returns the shellcheck diagnostics for a file's collected steps.
// When Precompute has run, results are served from the shared cache (keyed by
// run-value node) so the ordering matches the per-step path exactly. Otherwise
// it falls back to a per-file shellcheck invocation.
func (r *Rule) resultsFor(steps []shellStep) []*diagnostic.Error {
	if len(steps) == 0 {
		return nil
	}
	if !r.precomputed.Load() {
		// No global precompute (e.g. unit tests): lint this file directly.
		return r.checkSteps(steps)
	}
	// Wait until precompute has populated the cache. When ready is nil the cache
	// was populated synchronously before analysis (Precompute without
	// BeginPrecompute), so no wait is needed.
	if r.ready != nil {
		<-r.ready
	}
	var errs []*diagnostic.Error
	for _, s := range steps {
		runKV := s.step.FindKey("run")
		if runKV == nil {
			continue
		}
		if v, ok := r.cache.Load(runKV.Value); ok {
			errs = append(errs, v.([]*diagnostic.Error)...)
		}
	}
	return errs
}

// preparedStep holds the masking result for a single analyzable run step, ready
// to be linted by shellcheck and mapped back to YAML positions.
type preparedStep struct {
	node    ast.Node // the run value node, used to compute YAML span positions
	value   string   // original run script
	masked  string   // expression-masked script sent to shellcheck
	regions []maskRegion
	shell   string
}

// prepareSteps masks each step's run script for shellcheck. The returned slice
// is parallel to steps (nil where a step is not analyzable). eligible reports
// whether at least one analyzable shell run step was present, which drives the
// "install shellcheck" hint when the binary is unavailable.
func prepareSteps(steps []shellStep) (prepared []*preparedStep, eligible bool) {
	prepared = make([]*preparedStep, len(steps))
	for i, s := range steps {
		runKV := s.step.FindKey("run")
		if runKV == nil {
			continue
		}
		value := rules.StringValue(runKV.Value)
		if value == "" {
			continue
		}
		// An analyzable shell run step was found; it would have been linted had
		// the binary been available.
		eligible = true
		masked, regions, malformed := maskExpressions(value)
		if malformed {
			// A malformed ${{ }} expression could not be masked; running
			// shellcheck on the broken syntax would only produce noise. The
			// malformed expression is reported by invalid-expression.
			continue
		}
		prepared[i] = &preparedStep{
			node:    runKV.Value,
			value:   value,
			masked:  masked,
			regions: regions,
			shell:   s.shell,
		}
	}
	return prepared, eligible
}

// lintPrepared groups prepared steps by shell, runs shellcheck once per shell
// (the -s dialect applies to the whole batch), and writes the interpreted
// diagnostics into perStep, indexed parallel to prepared. The dominant
// per-process startup cost is thus paid once per shell rather than once per
// script. perStep must have len(prepared) slots.
func (r *Rule) lintPrepared(prepared []*preparedStep, perStep [][]*diagnostic.Error) {
	type group struct {
		indexes []int
		scripts []string
	}
	var shells []string
	byShell := map[string]*group{}
	for i, p := range prepared {
		if p == nil {
			continue
		}
		g := byShell[p.shell]
		if g == nil {
			g = &group{}
			byShell[p.shell] = g
			shells = append(shells, p.shell)
		}
		g.indexes = append(g.indexes, i)
		g.scripts = append(g.scripts, p.masked)
	}

	for _, shell := range shells {
		g := byShell[shell]
		execSem <- struct{}{}
		results, err := r.Runner.RunBatch(context.Background(), shell, g.scripts)
		<-execSem
		if err != nil {
			// shellcheck could not process the batch; skip silently.
			continue
		}
		for j, idx := range g.indexes {
			if j >= len(results) {
				continue
			}
			perStep[idx] = interpretComments(prepared[idx], results[j])
		}
	}
}

// Precompute lints every run step across all workflow and action files in a
// single shellcheck invocation per shell, caching the resulting diagnostics by
// run-value AST node. cmd/root calls it once, after parsing and before the
// per-file analysis pass, so CheckWorkflow/CheckAction can serve results from
// the cache instead of forking shellcheck per file. Batching globally collapses
// what would be one process spawn per file (the dominant cost on large repos)
// into one spawn per shell.
//
// The cache is always initialized (so resultsFor takes the cache path even when
// no steps are eligible). When the binary is unavailable, only sawEligibleStep
// is updated and the cache stays empty.
func (r *Rule) Precompute(workflows []workflow.WorkflowMapping, actions []workflow.ActionMapping) {
	var steps []shellStep
	for _, m := range workflows {
		steps = append(steps, collectWorkflowSteps(m)...)
	}
	for _, m := range actions {
		steps = append(steps, collectActionSteps(m)...)
	}
	r.precomputeSteps(steps)
}

// precomputeSteps lints the given steps and merges their diagnostics into the
// cache (keyed by run-value node). It may be called more than once — e.g. with
// workflow steps and action steps separately, so the workflow batch can run
// concurrently with the (slow) recursive action discovery — and accumulates into
// the same cache. The cache is initialized even when there are no steps, so
// resultsFor always takes the cache path once any Precompute call has run.
func (r *Rule) precomputeSteps(steps []shellStep) {
	r.precomputed.Store(true)

	if len(steps) == 0 {
		return
	}

	prepared, eligible := prepareSteps(steps)
	if !r.Runner.Available() {
		if eligible {
			r.sawEligibleStep.Store(true)
		}
		return
	}

	perStep := make([][]*diagnostic.Error, len(prepared))
	r.lintPreparedParallel(prepared, perStep)

	for i, p := range prepared {
		if p == nil || len(perStep[i]) == 0 {
			continue
		}
		r.cache.Store(p.node, perStep[i])
	}
}

// lintPreparedParallel lints prepared steps with shellcheck and writes the
// interpreted diagnostics into perStep (indexed parallel to prepared, which must
// have len(prepared) slots).
//
// Two optimizations keep this fast on large repos:
//   - Deduplication: identical scripts (same shell + masked text) are analyzed
//     once. Real workflows repeat the same setup snippets across many jobs, so
//     this cuts the script count shellcheck must process. Findings depend only on
//     the script text, so they are reused across every step sharing it (each step
//     still interprets them against its own YAML node for correct positions).
//   - Chunked parallelism: a single shellcheck process is single-threaded, so the
//     unique scripts are split into chunks (one shellcheck spawn each) sized to
//     the CPU count. This spreads the analysis across cores in roughly one wave
//     while amortizing the dominant process-startup cost once per core.
func (r *Rule) lintPreparedParallel(prepared []*preparedStep, perStep [][]*diagnostic.Error) {
	// Deduplicate by (shell, masked script). uniques holds one representative per
	// distinct script; dupeIndexes maps each unique to every prepared step that
	// shares it.
	type uniqueScript struct {
		shell  string
		script string
	}
	indexByScript := map[string]int{}
	var uniques []uniqueScript
	var dupeIndexes [][]int
	for i, p := range prepared {
		if p == nil {
			continue
		}
		key := p.shell + "\x00" + p.masked
		ui, ok := indexByScript[key]
		if !ok {
			ui = len(uniques)
			indexByScript[key] = ui
			uniques = append(uniques, uniqueScript{shell: p.shell, script: p.masked})
			dupeIndexes = append(dupeIndexes, nil)
		}
		dupeIndexes[ui] = append(dupeIndexes[ui], i)
	}
	if len(uniques) == 0 {
		return
	}

	// Group unique scripts by shell (the -s dialect applies to a whole batch).
	byShell := map[string][]int{}
	var shells []string
	for ui, u := range uniques {
		if _, seen := byShell[u.shell]; !seen {
			shells = append(shells, u.shell)
		}
		byShell[u.shell] = append(byShell[u.shell], ui)
	}

	// Choose a chunk count (each chunk is one shellcheck process). shellcheck's
	// per-process startup is a large, mostly fixed cost, so the workload is
	// startup-dominated: measurements show that fewer, larger chunks (≈ half the
	// cores) beat one-chunk-per-core, because halving the process count halves the
	// aggregate startup overhead while still keeping the cores busy. The walk and
	// the Go runtime also need cores. minChunkScripts then keeps chunks from
	// getting so small that startup dominates — important for the small action
	// batch, where a single spawn beats one per core.
	const minChunkScripts = 16
	target := max(runtime.NumCPU()/2, 2)
	if maxByScripts := (len(uniques) + minChunkScripts - 1) / minChunkScripts; target > maxByScripts {
		target = maxByScripts
	}
	if target < 1 {
		target = 1
	}
	chunkSize := (len(uniques) + target - 1) / target
	if chunkSize < 1 {
		chunkSize = 1
	}

	// comments holds shellcheck's raw findings per unique script.
	comments := make([][]Comment, len(uniques))

	type chunk struct {
		shell   string
		uindex  []int
		scripts []string
	}
	var chunks []chunk
	for _, shell := range shells {
		uis := byShell[shell]
		for start := 0; start < len(uis); start += chunkSize {
			end := min(start+chunkSize, len(uis))
			c := chunk{shell: shell}
			for _, ui := range uis[start:end] {
				c.uindex = append(c.uindex, ui)
				c.scripts = append(c.scripts, uniques[ui].script)
			}
			chunks = append(chunks, c)
		}
	}

	var wg sync.WaitGroup
	for _, c := range chunks {
		wg.Add(1)
		go func(c chunk) {
			defer wg.Done()
			execSem <- struct{}{}
			results, err := r.Runner.RunBatch(context.Background(), c.shell, c.scripts)
			<-execSem
			if err != nil {
				// shellcheck could not process the chunk; skip silently.
				return
			}
			for j, ui := range c.uindex {
				if j >= len(results) {
					continue
				}
				comments[ui] = results[j]
			}
		}(c)
	}
	wg.Wait()

	// Map each unique script's findings back onto every step that shares it,
	// interpreting against each step's own node for correct YAML positions.
	for ui, idxs := range dupeIndexes {
		cs := comments[ui]
		if len(cs) == 0 {
			continue
		}
		for _, idx := range idxs {
			perStep[idx] = interpretComments(prepared[idx], cs)
		}
	}
}

// checkSteps lints a single file's collected run steps directly. It is the
// fallback used when Precompute has not populated the cache (e.g. unit tests).
func (r *Rule) checkSteps(steps []shellStep) []*diagnostic.Error {
	if len(steps) == 0 {
		return nil
	}

	prepared, eligible := prepareSteps(steps)
	if !r.Runner.Available() {
		if eligible {
			r.sawEligibleStep.Store(true)
		}
		return nil
	}

	perStep := make([][]*diagnostic.Error, len(steps))
	r.lintPrepared(prepared, perStep)

	var errs []*diagnostic.Error
	for _, e := range perStep {
		errs = append(errs, e...)
	}
	return errs
}

// interpretComments maps shellcheck findings for a single masked script back to
// YAML-positioned diagnostics, dropping style-level findings and findings that
// fall entirely within masked expression placeholders.
func interpretComments(p *preparedStep, comments []Comment) []*diagnostic.Error {
	var errs []*diagnostic.Error
	for _, c := range comments {
		if c.Level == "style" {
			// Defensive: -S info already excludes style.
			continue
		}
		if isInsideMask(p.regions, c.Line, c.Column, c.EndColumn) {
			// shellcheck commenting on synthesized placeholder text.
			continue
		}
		tk := spanToken(p.node, p.value, p.masked, c.Line, c.Column, c.EndLine, c.EndColumn)
		errs = append(errs, &diagnostic.Error{
			Token:   tk,
			RuleID:  fmt.Sprintf("shellcheck/SC%d", c.Code),
			Ref:     fmt.Sprintf("https://www.shellcheck.net/wiki/SC%d", c.Code),
			Message: c.Message,
		})
	}
	return errs
}

// resolveEffectiveShell determines the shell string in effect for a step,
// following step.shell → job defaults → workflow defaults. The bool reports
// whether any level specified a shell.
func resolveEffectiveShell(step workflow.StepMapping, jobShell string, jobOK bool, wfShell string, wfOK bool) (string, bool) {
	if kv := step.FindKey("shell"); kv != nil {
		if s := rules.StringValue(kv.Value); s != "" {
			return s, true
		}
	}
	if jobOK {
		return jobShell, true
	}
	if wfOK {
		return wfShell, true
	}
	return "", false
}
