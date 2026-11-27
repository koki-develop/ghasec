package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root := flag.String("root", ".", "project root directory")
	schemaType := flag.String("schema", "all", "which schema to generate: workflow, action, or all")
	flag.Parse()

	schemaDir := filepath.Join(*root, "schemastore/src/schemas/json")
	outputDir := filepath.Join(*root, "rules")

	generateWorkflow := *schemaType == "all" || *schemaType == "workflow"
	generateAction := *schemaType == "all" || *schemaType == "action"

	if generateWorkflow {
		workflowSchemaPath := filepath.Join(schemaDir, "github-workflow.json")
		s, err := loadSchema(workflowSchemaPath, workflowOverrides)
		if err != nil {
			return fmt.Errorf("loading workflow schema: %w", err)
		}
		ir := convert(s, "")
		e := &emitter{}
		e.EmitValidateFunc("validateWorkflow", "workflow.WorkflowMapping", ir)
		if err := generateFile(generateParams{
			PackageName: "invalidworkflow", Regexps: e.regexps, ValidatorFunc: e.String(),
		}, filepath.Join(outputDir, "invalid-workflow/generated.go")); err != nil {
			return err
		}
		fmt.Println("Generated rules/invalid-workflow/generated.go")
	}

	if generateAction {
		s, err := loadSchema(filepath.Join(schemaDir, "github-action.json"), actionOverrides)
		if err != nil {
			return fmt.Errorf("loading action schema: %w", err)
		}
		ir := convert(s, "")
		e := &emitter{}
		e.EmitValidateFunc("validateAction", "workflow.ActionMapping", ir)
		if err := generateFile(generateParams{
			PackageName: "invalidaction", Regexps: e.regexps, ValidatorFunc: e.String(),
		}, filepath.Join(outputDir, "invalid-action/generated.go")); err != nil {
			return err
		}
		fmt.Println("Generated rules/invalid-action/generated.go")
	}

	return nil
}
