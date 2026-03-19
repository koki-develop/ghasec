package renderer

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/goccy/go-yaml/token"
	"github.com/koki-develop/annotate-go"
	"github.com/koki-develop/ghasec/diagnostic"
)

// Renderer handles diagnostic error rendering with consistent styling.
// NO_COLOR is resolved once at construction time.
type Renderer struct {
	noColor bool
}

// New creates a Renderer. It checks the NO_COLOR environment variable once.
func New() *Renderer {
	_, noColor := os.LookupEnv("NO_COLOR")
	return &Renderer{noColor: noColor}
}

// yamlError is the interface that goccy/go-yaml parse errors implement.
type yamlError interface {
	GetToken() *token.Token
	GetMessage() string
}

// PrintParseError renders a YAML parse error with source annotation.
func (r *Renderer) PrintParseError(path string, err error) error {
	yErr, ok := err.(yamlError)
	if !ok {
		return fmt.Errorf("unexpected parse error type for %s: %w", path, err)
	}
	tk := yErr.GetToken()
	if !isValidToken(tk) {
		return fmt.Errorf("parse error without position for %s: %s", path, yErr.GetMessage())
	}
	return r.printAnnotatedError(path, tk, yErr.GetMessage(), "", nil, nil, nil)
}

// PrintDiagnosticError renders a diagnostic error with source annotation.
func (r *Renderer) PrintDiagnosticError(path string, e *diagnostic.Error) error {
	if !isValidToken(e.Token) {
		return fmt.Errorf("diagnostic error without position for %s: %s", path, e.Message)
	}
	message := e.Message
	var ruleRef string
	if e.RuleID != "" {
		message = fmt.Sprintf("%s (%s)", e.Message, e.RuleID)
		url := fmt.Sprintf("https://github.com/koki-develop/ghasec/blob/main/rules/%s/README.md", e.RuleID)
		if r.noColor {
			ruleRef = fmt.Sprintf("  Ref: %s", url)
		} else {
			ruleRef = fmt.Sprintf("  %s %s", annotate.Dim("Ref:"), annotate.ComposeStyles(annotate.Dim, annotate.Italic)(url))
		}
	}
	contextTokens := make([]*token.Token, 0, len(e.ContextTokens))
	for _, ct := range e.ContextTokens {
		if isValidToken(ct) {
			contextTokens = append(contextTokens, ct)
		}
	}
	sort.Slice(contextTokens, func(i, j int) bool {
		return contextTokens[i].Position.Offset < contextTokens[j].Position.Offset
	})

	var before *int
	if len(contextTokens) > 0 {
		one := 1
		before = &one
	}

	return r.printAnnotatedError(path, e.Token, message, ruleRef, before, contextTokens, e.Markers)
}

func isValidToken(tk *token.Token) bool {
	return tk != nil && tk.Position != nil
}

// tokenSpan converts a YAML token's position into an annotate.Span over src.
// The token's Offset is 1-based, so it is adjusted to 0-based. The span is
// clamped to a single line and guaranteed to have non-zero length.
func tokenSpan(src []byte, tk *token.Token) annotate.Span {
	start := min(max(tk.Position.Offset-1, 0), len(src))
	end := min(start+len(tk.Value), len(src))
	if idx := bytes.IndexByte(src[start:end], '\n'); idx >= 0 {
		end = start + idx
	}
	span := annotate.Span{Start: start, End: end}
	if span.End <= span.Start {
		span.End = span.Start + 1
	}
	return span
}

func (r *Renderer) printAnnotatedError(path string, tk *token.Token, message string, ruleRef string, before *int, contextTokens []*token.Token, markerTokens []*token.Token) error {
	src, readErr := os.ReadFile(path)
	if readErr != nil {
		return fmt.Errorf("failed to read source file %s: %w", path, readErr)
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte(" \n")
	}

	label := annotate.Label{
		Span:   tokenSpan(src, tk),
		Marker: annotate.MarkerCaret,
		Text:   message,
		Before: before,
	}
	if !r.noColor {
		label.Style = annotate.LabelStyle{
			Marker:    annotate.FgRed,
			LabelText: annotate.ComposeStyles(annotate.FgRed, annotate.Bold),
		}
	}

	labels := []annotate.Label{label}
	for _, ct := range contextTokens {
		if !isValidToken(ct) {
			continue
		}
		labels = append(labels, annotate.Label{
			Span:   tokenSpan(src, ct),
			Marker: annotate.MarkerNone,
		})
	}
	for _, mt := range markerTokens {
		if !isValidToken(mt) {
			continue
		}
		ml := annotate.Label{
			Span:   tokenSpan(src, mt),
			Marker: annotate.MarkerCaret,
		}
		if !r.noColor {
			ml.Style = annotate.LabelStyle{
				Marker: annotate.FgYellow,
			}
		}
		labels = append(labels, ml)
	}

	var opts []annotate.Option
	if !r.noColor {
		opts = append(opts, annotate.WithStyle(annotate.DefaultStyle))
		opts = append(opts, annotate.WithSourceStyle(func(s string) string {
			var buf strings.Builder
			if err := quick.Highlight(&buf, s, "yaml", "terminal256", "github-dark"); err != nil {
				return s
			}
			return buf.String()
		}))
	}
	a := annotate.New(opts...)
	output, renderErr := a.Render(src, labels)
	if renderErr != nil {
		return fmt.Errorf("failed to render annotation for %s: %w", path, renderErr)
	}

	arrow := "-->"
	displayPath := fmt.Sprintf("%s:%d:%d", path, tk.Position.Line, tk.Position.Column)
	if !r.noColor {
		arrow = annotate.ComposeStyles(annotate.FgCyan, annotate.Bold)("-->")
		displayPath = annotate.Bold(displayPath)
	}
	if ruleRef != "" {
		fmt.Fprintf(os.Stderr, "%s %s\n%s%s\n\n", arrow, displayPath, output, ruleRef)
	} else {
		fmt.Fprintf(os.Stderr, "%s %s\n%s\n", arrow, displayPath, output)
	}
	return nil
}
