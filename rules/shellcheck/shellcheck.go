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
}

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

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
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
	return r.checkSteps(steps)
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
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
	return r.checkSteps(steps)
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

// checkSteps lints every collected run step and returns the merged diagnostics.
// Scripts are masked, grouped by shell, and handed to shellcheck in a single
// batched invocation per shell (the -s dialect applies to the whole batch), so
// the dominant per-process startup cost is paid once per file instead of once
// per step. Results are written to a per-index slot so the final ordering is
// deterministic (identical to the previous per-step implementation), which the
// analyzer then re-sorts by position anyway.
func (r *Rule) checkSteps(steps []shellStep) []*diagnostic.Error {
	if len(steps) == 0 {
		return nil
	}

	available := r.Runner.Available()
	prepared := make([]*preparedStep, len(steps))
	eligible := false
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
		if !available {
			continue
		}
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

	if !available {
		if eligible {
			r.sawEligibleStep.Store(true)
		}
		return nil
	}

	// Group prepared steps by shell, preserving original step indexes so results
	// can be mapped back deterministically.
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

	perStep := make([][]*diagnostic.Error, len(steps))
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

