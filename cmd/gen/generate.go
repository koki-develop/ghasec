package main

import (
	"bytes"
	"embed"
	"fmt"
	"go/format"
	"os"
	"text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

type generateParams struct {
	PackageName   string
	Regexps       []regexpVar
	ValidatorFunc string
}

type regexpVar struct {
	VarName string
	Pattern string
}

func generateFile(params generateParams, outputPath string) error {
	tmpl, err := template.ParseFS(templateFS, "templates/validator.go.tmpl")
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("formatting generated code: %w\n\nRaw output:\n%s", err, buf.String())
	}

	if err := os.WriteFile(outputPath, formatted, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", outputPath, err)
	}

	return nil
}
