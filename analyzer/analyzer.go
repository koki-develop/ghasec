package analyzer

import (
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
)

type DiagnosticError struct {
	Token   *token.Token
	Message string
}

func (e *DiagnosticError) Error() string          { return e.Message }
func (e *DiagnosticError) GetToken() *token.Token { return e.Token }
func (e *DiagnosticError) GetMessage() string     { return e.Message }

func Analyze(f *ast.File) []*DiagnosticError {
	if len(f.Docs) == 0 || f.Docs[0] == nil || f.Docs[0].Body == nil {
		return nil
	}

	mapping := topLevelMapping(f.Docs[0])
	if mapping == nil {
		return []*DiagnosticError{{
			Token:   f.Docs[0].Body.GetToken(),
			Message: "workflow must be a mapping",
		}}
	}

	var errs []*DiagnosticError
	errs = append(errs, checkOn(mapping)...)

	jobsMapping, jobsErrs := checkJobs(mapping)
	errs = append(errs, jobsErrs...)

	if jobsMapping != nil {
		errs = append(errs, checkJobEntries(jobsMapping)...)
	}

	return errs
}
