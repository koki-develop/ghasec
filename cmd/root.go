package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/discover"
	"github.com/koki-develop/ghasec/parser"
	"github.com/koki-develop/ghasec/renderer"
	"github.com/koki-develop/ghasec/rules"
	checkoutpersistcredentials "github.com/koki-develop/ghasec/rules/checkout-persist-credentials"
	defaultpermissions "github.com/koki-develop/ghasec/rules/default-permissions"
	invalidaction "github.com/koki-develop/ghasec/rules/invalid-action"
	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	mismatchedshatag "github.com/koki-develop/ghasec/rules/mismatched-sha-tag"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
	"github.com/spf13/cobra"
)

var errValidationFailed = errors.New("validation errors found")

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

		a := analyzer.New(activeRules...)
		_, envNoColor := os.LookupEnv("NO_COLOR")
		rdr := renderer.New(noColor || envNoColor)

		var errorCount int
		var errorFileCount int

		for _, f := range files.Workflows {
			astFile, err := parser.Parse(f)
			if err != nil {
				if printErr := rdr.PrintParseError(f, err); printErr != nil {
					return printErr
				}
				errorCount++
				errorFileCount++
				continue
			}
			errs := a.AnalyzeWorkflow(astFile)
			if len(errs) > 0 {
				for _, e := range errs {
					if err := rdr.PrintDiagnosticError(f, e); err != nil {
						return err
					}
				}
				errorCount += len(errs)
				errorFileCount++
			}
		}

		for _, f := range files.Actions {
			astFile, err := parser.Parse(f)
			if err != nil {
				if printErr := rdr.PrintParseError(f, err); printErr != nil {
					return printErr
				}
				errorCount++
				errorFileCount++
				continue
			}
			errs := a.AnalyzeAction(astFile)
			if len(errs) > 0 {
				for _, e := range errs {
					if err := rdr.PrintDiagnosticError(f, e); err != nil {
						return err
					}
				}
				errorCount += len(errs)
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
		&mismatchedshatag.Rule{},
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

func Execute() error {
	err := rootCmd.Execute()
	if err != nil && !errors.Is(err, errValidationFailed) {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
	}
	return err
}
