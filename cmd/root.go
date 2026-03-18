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
	"github.com/koki-develop/ghasec/rules/shapin"
	"github.com/koki-develop/ghasec/rules/workflow"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "ghasec [files...]",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		files, err := resolveFiles(args)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return errors.New("no workflow files found")
		}

		a := analyzer.New(
			&workflow.Rule{},
			&shapin.Rule{},
		)

		var hasErrors bool
		for _, f := range files {
			astFile, err := parser.Parse(f)
			if err != nil {
				hasErrors = true
				printParseError(f, err)
				continue
			}
			errs := a.Analyze(astFile)
			if len(errs) > 0 {
				hasErrors = true
				for _, e := range errs {
					printDiagnosticError(f, e)
				}
			}
		}
		if hasErrors {
			return errors.New("validation errors found")
		}
		return nil
	},
}

func resolveFiles(args []string) ([]string, error) {
	if len(args) > 0 {
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

func printParseError(path string, err error) {
	yErr, ok := err.(yamlError)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
		return
	}
	tk := yErr.GetToken()
	if tk == nil || tk.Position == nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
		return
	}
	printAnnotatedError(path, tk, yErr.GetMessage())
}

func printDiagnosticError(path string, e *diagnostic.Error) {
	if e.Token == nil || e.Token.Position == nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, e.Message)
		return
	}
	printAnnotatedError(path, e.Token, e.Message)
}

func printAnnotatedError(path string, tk *token.Token, message string) {
	src, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, message)
		return
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte(" \n")
	}

	start := tk.Position.Offset - 1
	if start < 0 {
		start = 0
	}
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
			SpanCode:  annotate.Bold,
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
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, message)
		return
	}

	fmt.Fprintf(os.Stderr, "%s:\n%s\n", path, output)
}

func Execute() error {
	return rootCmd.Execute()
}
