package cmd

import "fmt"

// Format represents the output format for ghasec diagnostics.
type Format string

const (
	FormatDefault       Format = "default"
	FormatGitHubActions Format = "github-actions"
	FormatMarkdown      Format = "markdown"
	FormatSARIF         Format = "sarif"
)

// IsValid reports whether f is a recognized output format.
func (f Format) IsValid() bool {
	switch f {
	case FormatDefault, FormatGitHubActions, FormatMarkdown, FormatSARIF:
		return true
	}
	return false
}

// Set implements pflag.Value. It validates the format string and sets f.
func (f *Format) Set(s string) error {
	v := Format(s)
	if !v.IsValid() {
		return fmt.Errorf("unknown format %q; must be \"default\", \"github-actions\", \"markdown\", or \"sarif\"", s)
	}
	*f = v
	return nil
}

// String implements pflag.Value.
func (f Format) String() string { return string(f) }

// Type implements pflag.Value. Returns "string" for CLI help display.
func (f Format) Type() string { return "string" }
