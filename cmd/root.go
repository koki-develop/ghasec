package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/annotate-go"
	"github.com/koki-develop/ghasec/analyzer"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/discover"
	"github.com/koki-develop/ghasec/parser"
	invalidworkflow "github.com/koki-develop/ghasec/rules/invalid-workflow"
	unpinnedaction "github.com/koki-develop/ghasec/rules/unpinned-action"
	"github.com/spf13/cobra"
)

var errValidationFailed = errors.New("validation errors found")

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

		a := analyzer.New(
			&invalidworkflow.Rule{},
			&unpinnedaction.Rule{},
		)

		var errorCount int
		var errorFileCount int
		for _, f := range files {
			astFile, err := parser.Parse(f)
			if err != nil {
				if err := printParseError(f, err); err != nil {
					return err
				}
				errorCount++
				errorFileCount++
				continue
			}
			errs := a.Analyze(astFile)
			if len(errs) > 0 {
				for _, e := range errs {
					if err := printDiagnosticError(f, e); err != nil {
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

// yamlError は goccy/go-yaml のパースエラーが実装する interface。
// パースエラーのソースアノテーション表示に使用する。
type yamlError interface {
	GetToken() *token.Token
	GetMessage() string
}

func printParseError(path string, err error) error {
	yErr, ok := err.(yamlError)
	if !ok {
		return fmt.Errorf("unexpected parse error type for %s: %w", path, err)
	}
	tk := yErr.GetToken()
	if tk == nil || tk.Position == nil {
		return fmt.Errorf("parse error without position for %s: %s", path, yErr.GetMessage())
	}
	return printAnnotatedError(path, tk, yErr.GetMessage(), "")
}

func printDiagnosticError(path string, e *diagnostic.Error) error {
	if e.Token == nil || e.Token.Position == nil {
		return fmt.Errorf("diagnostic error without position for %s: %s", path, e.Message)
	}
	message := e.Message
	var ruleRef string
	if e.RuleID != "" {
		message = fmt.Sprintf("%s (%s)", e.Message, e.RuleID)
		_, noColor := os.LookupEnv("NO_COLOR")
		url := fmt.Sprintf("https://github.com/koki-develop/ghasec/blob/main/rules/%s/README.md", e.RuleID)
		if noColor {
			ruleRef = fmt.Sprintf("  Ref: %s", url)
		} else {
			ruleRef = fmt.Sprintf("  %s %s", annotate.Dim("Ref:"), annotate.ComposeStyles(annotate.Dim, annotate.Italic)(url))
		}
	}
	return printAnnotatedError(path, e.Token, message, ruleRef)
}

func printAnnotatedError(path string, tk *token.Token, message string, ruleRef string) error {
	src, readErr := os.ReadFile(path)
	if readErr != nil {
		return fmt.Errorf("failed to read source file %s: %w", path, readErr)
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte(" \n")
	}

	start := max(tk.Position.Offset-1, 0)
	end := min(start+len(tk.Value), len(src))
	span := annotate.Span{
		Start: start,
		End:   end,
	}
	if span.End <= span.Start {
		span.End = span.Start + 1
	}

	_, noColor := os.LookupEnv("NO_COLOR")

	label := annotate.Label{
		Span:   span,
		Marker: annotate.MarkerCaret,
		Text:   message,
	}
	if !noColor {
		label.Style = annotate.LabelStyle{
			Marker:    annotate.FgRed,
			LabelText: annotate.ComposeStyles(annotate.FgRed, annotate.Bold),
		}
	}

	var opts []annotate.Option
	if !noColor {
		opts = append(opts, annotate.WithStyle(annotate.DefaultStyle))
	}
	r := annotate.New(opts...)
	output, renderErr := r.Render(src, []annotate.Label{label})
	if renderErr != nil {
		return fmt.Errorf("failed to render annotation for %s: %w", path, renderErr)
	}

	arrow := "-->"
	displayPath := path
	if !noColor {
		arrow = annotate.ComposeStyles(annotate.FgCyan, annotate.Bold)("-->")
		displayPath = annotate.Bold(path)
	}
	if ruleRef != "" {
		fmt.Fprintf(os.Stderr, "%s %s:\n%s%s\n\n", arrow, displayPath, output, ruleRef)
	} else {
		fmt.Fprintf(os.Stderr, "%s %s:\n%s\n", arrow, displayPath, output)
	}
	return nil
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
