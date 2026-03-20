package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/discover"
	ghclient "github.com/koki-develop/ghasec/github"
	"github.com/koki-develop/ghasec/parser"
	"github.com/koki-develop/ghasec/renderer"
	"github.com/koki-develop/ghasec/rules"
	checkoutpersistcredentials "github.com/koki-develop/ghasec/rules/checkout-persist-credentials"
	defaultpermissions "github.com/koki-develop/ghasec/rules/default-permissions"
	invalidaction "github.com/koki-develop/ghasec/rules/invalid-action"
	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	joballpermissions "github.com/koki-develop/ghasec/rules/job-all-permissions"
	mismatchedshatag "github.com/koki-develop/ghasec/rules/mismatched-sha-tag"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
	"github.com/spf13/cobra"
)

var errValidationFailed = errors.New("validation errors found")

const concurrency = 4

var (
	online  bool
	noColor bool
)

func init() {
	rootCmd.Flags().BoolVar(&online, "online", false, "enable rules that require network access")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "disable colored output")
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
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		files, err := resolveFiles(args)
		if err != nil {
			return err
		}
		if len(files.Workflows) == 0 && len(files.Actions) == 0 {
			return errors.New("no files found")
		}

		activeRules, skippedOnline := buildRules(online)

		if skippedOnline > 0 {
			defer func() {
				if _, disabled := os.LookupEnv("GHASEC_DISABLE_OFFLINE_WARNING"); !disabled {
					fmt.Fprintf(os.Stderr, "warning: %d online %s skipped; use --online to enable them\n",
						skippedOnline, pluralize("rule", skippedOnline))
				}
			}()
		}

		a := analyzer.New(concurrency, activeRules...)
		_, envNoColor := os.LookupEnv("NO_COLOR")
		rdr := renderer.New(noColor || envNoColor)

		var tasks []fileTask
		for _, f := range files.Workflows {
			tasks = append(tasks, fileTask{path: f, isAction: false})
		}
		for _, f := range files.Actions {
			tasks = append(tasks, fileTask{path: f, isAction: true})
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

		if errorCount > 0 {
			fmt.Fprintf(os.Stderr, "%d %s found in %d %s\n",
				errorCount, pluralize("error", errorCount),
				errorFileCount, pluralize("file", errorFileCount))
			return errValidationFailed
		}
		fmt.Fprintln(os.Stderr, "no errors found")
		return nil
	},
}

func buildRules(onlineEnabled bool) (active []rules.Rule, skippedOnline int) {
	all := []rules.Rule{
		&invalidworkflow.Rule{},
		&invalidaction.Rule{},
		&unpinnedaction.Rule{},
		&checkoutpersistcredentials.Rule{},
		&defaultpermissions.Rule{},
		&joballpermissions.Rule{},
		&mismatchedshatag.Rule{Resolver: newTagResolver()},
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

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

func newTagResolver() mismatchedshatag.TagResolver {
	var opts []ghclient.Option
	if baseURL := os.Getenv("GHASEC_GITHUB_API_URL"); baseURL != "" {
		opts = append(opts, ghclient.WithBaseURL(baseURL))
	}
	return ghclient.NewClient(opts...)
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil && !errors.Is(err, errValidationFailed) {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
	}
	return err
}
