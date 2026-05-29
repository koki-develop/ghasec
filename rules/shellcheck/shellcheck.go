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
	"sync/atomic"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "shellcheck"

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

func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	wfShell, wfOK := mapping.DefaultsRunShell()

	var errs []*diagnostic.Error
	mapping.EachJob(func(_ *token.Token, job workflow.JobMapping) {
		jobShell, jobOK := job.DefaultsRunShell()
		runsOn := job.RunsOnNode()
		job.EachStep(func(step workflow.StepMapping) {
			effShell, specified := resolveEffectiveShell(step, jobShell, jobOK, wfShell, wfOK)
			sh, target := resolveWorkflowTarget(effShell, specified, runsOn)
			if !target {
				return
			}
			errs = append(errs, r.checkRunStep(step, sh)...)
		})
	})
	return errs
}

func (r *Rule) CheckAction(mapping workflow.ActionMapping) []*diagnostic.Error {
	var errs []*diagnostic.Error
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
		errs = append(errs, r.checkRunStep(step, sh)...)
	})
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

// checkRunStep masks expressions, runs shellcheck, drops findings inside masked
// regions, and maps the rest back to YAML positions.
func (r *Rule) checkRunStep(step workflow.StepMapping, shell string) []*diagnostic.Error {
	runKV := step.FindKey("run")
	if runKV == nil {
		return nil
	}
	value := rules.StringValue(runKV.Value)
	if value == "" {
		return nil
	}

	// At this point the step is an analyzable shell run step.
	if !r.Runner.Available() {
		r.sawEligibleStep.Store(true)
		return nil
	}

	masked, regions, malformed := maskExpressions(value)
	if malformed {
		// The run contains a malformed ${{ }} expression that could not be
		// masked; running shellcheck on the broken syntax would only produce
		// noise. The malformed expression is reported by invalid-expression.
		return nil
	}
	comments, err := r.Runner.Run(context.Background(), shell, masked)
	if err != nil {
		// shellcheck could not process the input; skip silently.
		return nil
	}

	var errs []*diagnostic.Error
	for _, c := range comments {
		if c.Level == "style" {
			// Defensive: -S info already excludes style.
			continue
		}
		if isInsideMask(regions, c.Line, c.Column, c.EndColumn) {
			// shellcheck commenting on synthesized placeholder text.
			continue
		}
		tk := spanToken(runKV.Value, value, masked, c.Line, c.Column, c.EndLine, c.EndColumn)
		errs = append(errs, &diagnostic.Error{
			Token:   tk,
			RuleID:  fmt.Sprintf("shellcheck/SC%d", c.Code),
			Ref:     fmt.Sprintf("https://www.shellcheck.net/wiki/SC%d", c.Code),
			Message: c.Message,
		})
	}
	return errs
}
