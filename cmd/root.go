package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/discover"
	ghclient "github.com/koki-develop/ghasec/github"
	"github.com/koki-develop/ghasec/parser"
	"github.com/koki-develop/ghasec/renderer"
	"github.com/koki-develop/ghasec/rules"
	checkoutpersistcredentials "github.com/koki-develop/ghasec/rules/checkout-persist-credentials"
	defaultpermissions "github.com/koki-develop/ghasec/rules/default-permissions"
	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	mismatchedshatag "github.com/koki-develop/ghasec/rules/mismatched-sha-tag"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
	"github.com/spf13/cobra"
)

var errValidationFailed = errors.New("validation errors found")

var online bool

func init() {
	rootCmd.Flags().BoolVar(&online, "online", false, "enable rules that require network access")
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
		if len(files) == 0 {
			return errors.New("no workflow files found")
		}

		var ghOpts []ghclient.Option
		if baseURL := os.Getenv("GHASEC_GITHUB_API_URL"); baseURL != "" {
			ghOpts = append(ghOpts, ghclient.WithBaseURL(baseURL))
		}
		gh := ghclient.NewClient(ghOpts...)

		allRules := []rules.Rule{
			&invalidworkflow.Rule{},
			&unpinnedaction.Rule{},
			&checkoutpersistcredentials.Rule{},
			&defaultpermissions.Rule{},
			&mismatchedshatag.Rule{Resolver: gh},
		}

		var activeRules []rules.Rule
		var skippedOnline int
		for _, r := range allRules {
			if r.Online() && !online {
				skippedOnline++
				continue
			}
			activeRules = append(activeRules, r)
		}

		if skippedOnline > 0 {
			defer func() {
				if _, disabled := os.LookupEnv("GHASEC_DISABLE_OFFLINE_WARNING"); !disabled {
					fmt.Fprintf(os.Stderr, "Warning: %d online %s skipped. Use --online to enable them.\n",
						skippedOnline, pluralize("rule", skippedOnline))
				}
			}()
		}

		a := analyzer.New(activeRules...)
		rdr := renderer.New()

		var errorCount int
		var errorFileCount int
		for _, f := range files {
			astFile, err := parser.Parse(f)
			if err != nil {
				if printErr := rdr.PrintParseError(f, err); printErr != nil {
					return printErr
				}
				errorCount++
				errorFileCount++
				continue
			}
			errs := a.Analyze(astFile)
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
		fmt.Fprintln(os.Stderr, "No errors found.")
		return nil
	},
}

func resolveFiles(args []string) ([]string, error) {
	if len(args) > 0 {
		for _, arg := range args {
			info, err := os.Stat(arg)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				return nil, fmt.Errorf("%s is a directory; specify workflow files directly", arg)
			}
		}
		return args, nil
	}
	return discover.Discover(".")
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
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
	return err
}
