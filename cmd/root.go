package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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
	missingsharefcomment "github.com/koki-develop/ghasec/rules/missing-sha-ref-comment"
	scriptinjection "github.com/koki-develop/ghasec/rules/script-injection"
	secretsinherit "github.com/koki-develop/ghasec/rules/secrets-inherit"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
	unpinnedcontainer "github.com/koki-develop/ghasec/rules/unpinned-container"
	"github.com/koki-develop/ghasec/update"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var errValidationFailed = errors.New("validation errors found")

const concurrency = 4

var (
	online  bool
	noColor bool
	format  string
)

func init() {
	rootCmd.Version = resolveVersion()
	rootCmd.Flags().BoolVar(&online, "online", false, "enable rules that require network access")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "disable colored output")
	rootCmd.Flags().StringVar(&format, "format", "default", `output format ("default", "github-actions", or "markdown")`)
}

type classifiedFiles struct {
	Workflows []string
	Actions   []string
}

type fileTask struct {
	path     string
	isAction bool
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
		if format != "default" && format != "github-actions" && format != "markdown" {
			return fmt.Errorf("unknown format %q; must be \"default\", \"github-actions\", or \"markdown\"", format)
		}

		files, err := resolveFiles(args)
		if err != nil {
			return err
		}
		if len(files.Workflows) == 0 && len(files.Actions) == 0 {
			return errors.New("no files found")
		}

		activeRules, skippedOnline, ghClient := buildRules(online)
		if _, disabled := os.LookupEnv("GHASEC_DISABLE_OFFLINE_WARNING"); disabled {
			skippedOnline = 0
		}

		var updateCh <-chan *update.Result
		if _, disabled := os.LookupEnv("GHASEC_DISABLE_UPDATE_CHECK"); !disabled {
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
		case "github-actions":
			rdr = renderer.NewGitHubActions()
		case "markdown":
			rdr = renderer.NewMarkdown(activeRules)
		default:
			rdr = renderer.NewDefault(disableColor)
		}

		var tasks []fileTask
		for _, f := range files.Workflows {
			tasks = append(tasks, fileTask{path: f, isAction: false})
		}
		for _, f := range files.Actions {
			tasks = append(tasks, fileTask{path: f, isAction: true})
		}

		// Progress tracking setup
		totalRuleExecs := len(files.Workflows)*a.WorkflowRuleCount() + len(files.Actions)*a.ActionRuleCount()
		a.InitProgress(totalRuleExecs)

		// Progress bar setup (only when stderr is a TTY and default format)
		var prog *progress.Progress
		stderrFd := int(os.Stderr.Fd())
		if format == "default" && term.IsTerminal(stderrFd) {
			prog = progress.New(os.Stderr, stderrFd, disableColor)
			defer prog.Clear()
			a.SetProgressCallback(func(s progress.Status) {
				prog.Update(s)
			})
		}

		results := make([]fileResult, len(tasks))
		fileSem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for i, task := range tasks {
			wg.Add(1)
			go func(i int, task fileTask) {
				defer wg.Done()
				fileSem <- struct{}{}
				defer func() { <-fileSem }()

				astFile, err := parser.Parse(task.path)
				if err != nil {
					results[i] = fileResult{path: task.path, parseErr: err}
					ruleCount := a.WorkflowRuleCount()
					if task.isAction {
						ruleCount = a.ActionRuleCount()
					}
					a.AdjustTotal(-ruleCount)
					return
				}

				var errs []*diagnostic.Error
				if task.isAction {
					errs = a.AnalyzeAction(astFile)
				} else {
					errs = a.AnalyzeWorkflow(astFile)
				}
				results[i] = fileResult{path: task.path, diagErrs: errs}
			}(i, task)
		}
		wg.Wait()

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

		if err := rdr.PrintSummary(len(tasks), errorCount, errorFileCount, skippedOnline); err != nil {
			return err
		}

		if ghClient.RateLimitHit() && !ghClient.HasToken() {
			if err := rdr.PrintHint("set the GITHUB_TOKEN environment variable to increase the GitHub API rate limit"); err != nil {
				return err
			}
		}

		if updateCh != nil && format == "default" {
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

func buildRules(onlineEnabled bool) (active []rules.Rule, skippedOnline int, client *ghclient.Client) {
	client = newGitHubClient()
	all := []rules.Rule{
		&invalidworkflow.Rule{},
		&invalidaction.Rule{},
		&invalidexpression.Rule{},
		&unpinnedaction.Rule{},
		&unpinnedcontainer.Rule{},
		&checkoutpersistcredentials.Rule{},
		&dangerouscheckout.Rule{},
		&defaultpermissions.Rule{},
		&joballpermissions.Rule{},
		&jobtimeoutminutes.Rule{},
		&secretsinherit.Rule{},
		&scriptinjection.Rule{},
		&deprecatedcommands.Rule{},
		&missingsharefcomment.Rule{},
		&actorbotcheck.Rule{},
		&impostorcommit.Rule{Verifier: client},
		&mismatchedshatag.Rule{Resolver: client},
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

func resolveFiles(args []string) (classifiedFiles, error) {
	if len(args) > 0 {
		var cf classifiedFiles
		for _, arg := range args {
			info, err := os.Stat(arg)
			if err != nil {
				return classifiedFiles{}, err
			}
			if info.IsDir() {
				return classifiedFiles{}, fmt.Errorf("%s is a directory; specify files directly", arg)
			}
			switch classifyFile(arg) {
			case "action":
				cf.Actions = append(cf.Actions, arg)
			default:
				cf.Workflows = append(cf.Workflows, arg)
			}
		}
		sort.Strings(cf.Workflows)
		sort.Strings(cf.Actions)
		return cf, nil
	}
	res, err := discover.Discover(".")
	if err != nil {
		return classifiedFiles{}, err
	}
	return classifiedFiles{
		Workflows: res.Workflows,
		Actions:   res.Actions,
	}, nil
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
