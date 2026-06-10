package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml/ast"
	annotate "github.com/koki-develop/annotate-go"
	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/discover"
	ghclient "github.com/koki-develop/ghasec/github"
	"github.com/koki-develop/ghasec/parser"
	"github.com/koki-develop/ghasec/progress"
	"github.com/koki-develop/ghasec/renderer"
	"github.com/koki-develop/ghasec/rules"
	actorbotcheck "github.com/koki-develop/ghasec/rules/actor-bot-check"
	archivedaction "github.com/koki-develop/ghasec/rules/archived-action"
	broadsecretenv "github.com/koki-develop/ghasec/rules/broad-secret-env"
	checkoutpersistcredentials "github.com/koki-develop/ghasec/rules/checkout-persist-credentials"
	dangerouscheckout "github.com/koki-develop/ghasec/rules/dangerous-checkout"
	defaultpermissions "github.com/koki-develop/ghasec/rules/default-permissions"
	deprecatedcommands "github.com/koki-develop/ghasec/rules/deprecated-commands"
	impostorcommit "github.com/koki-develop/ghasec/rules/impostor-commit"
	invalidaction "github.com/koki-develop/ghasec/rules/invalid-action"
	invalidexpression "github.com/koki-develop/ghasec/rules/invalid-expression"
	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	joballpermissions "github.com/koki-develop/ghasec/rules/job-all-permissions"
	jobtimeoutminutes "github.com/koki-develop/ghasec/rules/job-timeout-minutes"
	mismatchedshatag "github.com/koki-develop/ghasec/rules/mismatched-sha-tag"
	missingapptokenpermissions "github.com/koki-develop/ghasec/rules/missing-app-token-permissions"
	missingsharefcomment "github.com/koki-develop/ghasec/rules/missing-sha-ref-comment"
	scriptinjection "github.com/koki-develop/ghasec/rules/script-injection"
	secretsinherit "github.com/koki-develop/ghasec/rules/secrets-inherit"
	shellcheckrule "github.com/koki-develop/ghasec/rules/shellcheck"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
	unpinnedcontainer "github.com/koki-develop/ghasec/rules/unpinned-container"
	unpinnedreusableworkflow "github.com/koki-develop/ghasec/rules/unpinned-reusable-workflow"
	unpinnedtransitiveaction "github.com/koki-develop/ghasec/rules/unpinned-transitive-action"
	"github.com/koki-develop/ghasec/update"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var errValidationFailed = errors.New("validation errors found")

var concurrency = max(runtime.NumCPU(), 4)

var (
	online  bool
	noColor bool
	format  Format = FormatDefault
	workdir string = "."
)

func init() {
	rootCmd.Version = resolveVersion()
	rootCmd.Flags().BoolVar(&online, "online", false, "enable rules that require network access")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "disable colored output")
	rootCmd.Flags().Var(&format, "format", `output format ("default", "github-actions", "markdown", or "sarif")`)
	rootCmd.Flags().StringVar(&workdir, "workdir", ".", "working directory")
}

type classifiedFiles struct {
	Workflows []string
	Actions   []string
}

type fileResult struct {
	path     string
	parseErr error
	diagErrs []*diagnostic.Error
}

func classifyFile(path string) string {
	clean := filepath.ToSlash(filepath.Clean(path))
	if strings.Contains(clean, ".github/workflows/") {
		return "workflow"
	}
	base := filepath.Base(path)
	if base == "action.yml" || base == "action.yaml" {
		return "action"
	}
	return "workflow"
}

var rootCmd = &cobra.Command{
	Use:           "ghasec [files...]",
	Long:          "Catch security risks in your GitHub Actions workflows.",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		workflowPaths, actionsFn, err := resolveFiles(args)
		if err != nil {
			return err
		}

		activeRules, skippedOnline, ghClient, shellcheckRule := buildRules(online)
		if _, disabled := os.LookupEnv("GHASEC_DISABLE_OFFLINE_WARNING"); disabled {
			skippedOnline = 0
		}

		// The update notification is only printed for the default format (see the
		// updateCh consumer below), so skip the check entirely for other formats:
		// its result would be discarded, and launching it only adds a goroutine and
		// a GitHub client request that contend with analysis.
		var updateCh <-chan *update.Result
		_, updateDisabled := os.LookupEnv("GHASEC_DISABLE_UPDATE_CHECK")
		if !updateDisabled && format == FormatDefault {
			ch := make(chan *update.Result, 1)
			updateCtx, updateCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer updateCancel()
			go func() {
				ch <- update.Check(updateCtx, ghClient, cmd.Version)
			}()
			updateCh = ch
		}

		a := analyzer.New(concurrency, activeRules...)
		_, envNoColor := os.LookupEnv("NO_COLOR")
		disableColor := noColor || envNoColor

		var rdr renderer.Renderer
		switch format {
		case FormatDefault:
			rdr = renderer.NewDefault(disableColor)
		case FormatGitHubActions:
			rdr = renderer.NewGitHubActions()
		case FormatMarkdown:
			rdr = renderer.NewMarkdown(activeRules)
		case FormatSARIF:
			rdr = renderer.NewSARIF(activeRules, cmd.Version)
		}

		// Progress bar setup (only when stderr is a TTY and default format).
		var prog *progress.Progress
		stderrFd := int(os.Stderr.Fd())
		if format == FormatDefault && term.IsTerminal(stderrFd) {
			prog = progress.New(os.Stderr, stderrFd, disableColor)
			defer prog.Clear()
			a.SetProgressCallback(func(s progress.Status) {
				prog.Update(s)
			})
		}

		// Progress total starts with the workflow rule executions; the action
		// count is only known once the background walk finishes, so it is added
		// once the actions are discovered below.
		a.InitProgress(len(workflowPaths) * a.WorkflowRuleCount())

		// analyzeSem bounds how many files are analyzed concurrently, capping
		// goroutine fan-out on very large repos. Parsing is intentionally not
		// gated (it is light, short-lived I/O, and the action batch parses inside
		// a precompute goroutine — gating both with one semaphore could deadlock
		// since analysis goroutines block on the shellcheck readiness gate).
		analyzeSem := make(chan struct{}, concurrency)

		// parseFiles parses paths concurrently, returning the ASTs (nil on parse
		// error) and the per-file results pre-populated with any parse errors.
		parseFiles := func(paths []string, isAction bool) ([]*ast.File, []fileResult) {
			asts := make([]*ast.File, len(paths))
			res := make([]fileResult, len(paths))
			var wg sync.WaitGroup
			for i, p := range paths {
				wg.Add(1)
				go func(i int, p string) {
					defer wg.Done()
					astFile, parseErr := parser.Parse(p)
					if parseErr != nil {
						res[i] = fileResult{path: p, parseErr: parseErr}
						ruleCount := a.WorkflowRuleCount()
						if isAction {
							ruleCount = a.ActionRuleCount()
						}
						a.AdjustTotal(-ruleCount)
						return
					}
					asts[i] = astFile
				}(i, p)
			}
			wg.Wait()
			return asts, res
		}

		// analyzeFiles runs the rules over each parsed file concurrently, writing
		// diagnostics into res. The shellcheck rule blocks until MarkReady, so the
		// other (cheap) rules run concurrently with the slow shellcheck precompute.
		analyzeFiles := func(paths []string, asts []*ast.File, res []fileResult, isAction bool) {
			var wg sync.WaitGroup
			for i := range paths {
				if asts[i] == nil {
					continue
				}
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					analyzeSem <- struct{}{}
					defer func() { <-analyzeSem }()

					var errs []*diagnostic.Error
					if isAction {
						errs = a.AnalyzeAction(asts[i])
					} else {
						errs = a.AnalyzeWorkflow(asts[i])
					}
					res[i] = fileResult{path: paths[i], diagErrs: errs}
				}(i)
			}
			wg.Wait()
		}

		shellcheckRule.BeginPrecompute()

		// Parse workflows up front; the background action walk runs concurrently.
		wfAsts, workflowResults := parseFiles(workflowPaths, false)

		// Kick off the workflow shellcheck precompute immediately so it overlaps
		// the still-running action walk (CPU-bound shellcheck vs I/O-bound walk).
		var pcWg sync.WaitGroup
		pcWg.Add(1)
		go func() {
			defer pcWg.Done()
			var ms []workflow.WorkflowMapping
			for i := range workflowPaths {
				if wfAsts[i] == nil {
					continue
				}
				if m, ok := analyzer.WorkflowMappingOf(wfAsts[i]); ok {
					ms = append(ms, m)
				}
			}
			shellcheckRule.Precompute(ms, nil)
		}()

		// Discover, parse and shellcheck the action files in their own goroutine so
		// the action shellcheck overlaps the workflow precompute pool (rather than
		// tailing it). The walk join, action parse, and action precompute all run
		// concurrently with the workflow batch.
		var (
			actionPaths   []string
			acAsts        []*ast.File
			actionResults []fileResult
		)
		pcWg.Add(1)
		go func() {
			defer pcWg.Done()
			actionPaths = actionsFn()
			a.AdjustTotal(len(actionPaths) * a.ActionRuleCount())
			acAsts, actionResults = parseFiles(actionPaths, true)
			var ms []workflow.ActionMapping
			for i := range actionPaths {
				if acAsts[i] == nil {
					continue
				}
				if m, ok := analyzer.ActionMappingOf(acAsts[i]); ok {
					ms = append(ms, m)
				}
			}
			shellcheckRule.Precompute(nil, ms)
		}()

		// Mark the shellcheck cache ready once both precompute batches finish.
		go func() {
			pcWg.Wait()
			shellcheckRule.MarkReady()
		}()

		// Analyze workflows now: the cheap rules run while the precompute proceeds;
		// the shellcheck rule blocks on MarkReady. All workflow files are already
		// parsed, so this never starves the action goroutine.
		analyzeFiles(workflowPaths, wfAsts, workflowResults, false)

		// Join the action goroutine (parse + precompute done), then analyze actions.
		pcWg.Wait()

		if len(workflowPaths) == 0 && len(actionPaths) == 0 {
			return errors.New("no files found")
		}

		analyzeFiles(actionPaths, acAsts, actionResults, true)

		results := append(workflowResults, actionResults...)

		// Clear progress bar before printing results.
		// defer above handles panic cleanup; this handles normal flow.
		if prog != nil {
			prog.Clear()
		}

		var errorCount int
		var errorFileCount int

		for _, r := range results {
			if r.parseErr != nil {
				if printErr := rdr.PrintParseError(r.path, r.parseErr); printErr != nil {
					return printErr
				}
				errorCount++
				errorFileCount++
				continue
			}
			if len(r.diagErrs) > 0 {
				for _, e := range r.diagErrs {
					if err := rdr.PrintDiagnosticError(r.path, e); err != nil {
						return err
					}
				}
				errorCount += len(r.diagErrs)
				errorFileCount++
			}
		}

		if err := rdr.PrintSummary(len(results), errorCount, errorFileCount, skippedOnline); err != nil {
			return err
		}

		if ghClient.RateLimitHit() && !ghClient.HasToken() {
			if err := rdr.PrintHint("set the GHASEC_GITHUB_TOKEN or GITHUB_TOKEN environment variable to increase the GitHub API rate limit"); err != nil {
				return err
			}
		}

		if !shellcheckRule.Runner.Available() && shellcheckRule.SawEligibleStep() {
			if err := rdr.PrintHint("install shellcheck to lint shell scripts: https://www.shellcheck.net"); err != nil {
				return err
			}
		}

		if updateCh != nil && format == FormatDefault {
			select {
			case res := <-updateCh:
				if res != nil && res.NewVersion != "" {
					printUpdateNotification(res, disableColor)
					update.MarkNotified(res.NewVersion)
				}
			case <-time.After(500 * time.Millisecond):
			}
		}

		if errorCount > 0 {
			return errValidationFailed
		}
		return nil
	},
}

func buildRules(onlineEnabled bool) (active []rules.Rule, skippedOnline int, client *ghclient.Client, shellcheckRule *shellcheckrule.Rule) {
	client = newGitHubClient()
	shellcheckRule = &shellcheckrule.Rule{Runner: shellcheckrule.NewExecRunner()}
	all := []rules.Rule{
		&invalidworkflow.Rule{},
		&invalidaction.Rule{},
		&invalidexpression.Rule{},
		&unpinnedaction.Rule{},
		&unpinnedcontainer.Rule{},
		&unpinnedreusableworkflow.Rule{},
		&checkoutpersistcredentials.Rule{},
		&dangerouscheckout.Rule{},
		&defaultpermissions.Rule{},
		&joballpermissions.Rule{},
		&jobtimeoutminutes.Rule{},
		&secretsinherit.Rule{},
		&scriptinjection.Rule{},
		shellcheckRule,
		&deprecatedcommands.Rule{},
		&missingsharefcomment.Rule{},
		&actorbotcheck.Rule{},
		&broadsecretenv.Rule{},
		&missingapptokenpermissions.Rule{},
		&archivedaction.Rule{Checker: client},
		&impostorcommit.Rule{Verifier: client},
		&mismatchedshatag.Rule{Resolver: client},
		&unpinnedtransitiveaction.Rule{Fetcher: client},
	}
	for _, r := range all {
		if r.Online() && !onlineEnabled {
			skippedOnline++
			continue
		}
		active = append(active, r)
	}
	return
}

// resolveFiles returns the workflow paths immediately and an actions thunk that
// yields the action paths. In auto-discover mode the (slow) recursive action
// walk runs in a background goroutine started here, so the caller can parse and
// shellcheck the workflows — which are known up front via a cheap glob — while
// the walk proceeds. The thunk joins the goroutine. In explicit-args mode both
// sets are known synchronously and the thunk just returns the actions.
func resolveFiles(args []string) (workflows []string, actions func() []string, err error) {
	if len(args) > 0 {
		var cf classifiedFiles
		for _, arg := range args {
			path := arg
			if !filepath.IsAbs(path) {
				path = filepath.Join(workdir, path)
			}
			info, statErr := os.Stat(path)
			if statErr != nil {
				return nil, nil, statErr
			}
			if info.IsDir() {
				return nil, nil, fmt.Errorf("%s is a directory; specify files directly", path)
			}
			switch classifyFile(path) {
			case "action":
				cf.Actions = append(cf.Actions, path)
			default:
				cf.Workflows = append(cf.Workflows, path)
			}
		}
		sort.Strings(cf.Workflows)
		sort.Strings(cf.Actions)
		return cf.Workflows, func() []string { return cf.Actions }, nil
	}

	wf, wfSet, err := discover.GlobWorkflows(workdir)
	if err != nil {
		return nil, nil, err
	}
	ch := make(chan []string, 1)
	go func() { ch <- discover.FindActions(workdir, wfSet) }()
	return wf, func() []string { return <-ch }, nil
}

func newGitHubClient() *ghclient.Client {
	var opts []ghclient.Option
	if baseURL := os.Getenv("GHASEC_GITHUB_API_URL"); baseURL != "" {
		opts = append(opts, ghclient.WithBaseURL(baseURL))
	}
	return ghclient.NewClient(opts...)
}

func printUpdateNotification(res *update.Result, noColor bool) {
	styled := func(fn func(string) string) func(string) string {
		if noColor {
			return func(s string) string { return s }
		}
		return fn
	}

	cyan := styled(annotate.FgCyan)
	bold := styled(annotate.Bold)
	dim := styled(annotate.Dim)

	fmt.Fprintf(os.Stderr, "\nA new version of ghasec is available: %s %s %s\n",
		res.CurrentVersion,
		cyan("→"),
		bold(res.NewVersion),
	)
	fmt.Fprintf(os.Stderr, "%s\n",
		dim(fmt.Sprintf("https://github.com/koki-develop/ghasec/releases/tag/v%s", res.NewVersion)),
	)
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil && !errors.Is(err, errValidationFailed) {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
	}
	return err
}
