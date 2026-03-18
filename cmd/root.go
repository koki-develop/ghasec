package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/annotate-go"
	"github.com/koki-develop/ghasec/discover"
	"github.com/koki-develop/ghasec/parser"
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

		var hasErrors bool
		for _, f := range files {
			if _, err := parser.Parse(f); err != nil {
				hasErrors = true
				printParseError(f, err)
			}
		}
		if hasErrors {
			return errors.New("parse errors found")
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

type yamlError interface {
	GetToken() *token.Token
	GetMessage() string
}

func printParseError(path string, err error) {
	var yErr yamlError
	if e, ok := err.(yamlError); ok {
		yErr = e
	}

	if yErr == nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
		return
	}

	tk := yErr.GetToken()
	if tk == nil || tk.Position == nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
		return
	}

	src, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
		return
	}

	end := tk.Position.Offset + len(tk.Origin)
	if end > len(src) {
		end = len(src)
	}
	span := annotate.Span{
		Start: tk.Position.Offset,
		End:   end,
	}
	if span.End <= span.Start {
		span.End = span.Start + 1
	}

	labels := []annotate.Label{
		{
			Span:   span,
			Marker: annotate.MarkerCaret,
			Text:   yErr.GetMessage(),
			Style:  annotate.LabelStyleError,
		},
	}

	r := annotate.New(annotate.WithStyle(annotate.DefaultStyle))
	output, renderErr := r.Render(src, labels)
	if renderErr != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
		return
	}

	fmt.Fprintf(os.Stderr, "%s:\n%s\n", path, output)
}

func Execute() error {
	return rootCmd.Execute()
}
