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
	return r.printAnnotatedError(annotationParams{
		path:    path,
		tk:      tk,
		message: yErr.GetMessage(),
	})
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
		ruleRef = fmt.Sprintf("  %s %s",
			r.styled(annotate.Dim)("Ref:"),
			r.styled(annotate.ComposeStyles(annotate.Dim, annotate.Italic))(url))
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

	return r.printAnnotatedError(annotationParams{
		path:          path,
		tk:            e.Token,
		message:       message,
		ruleRef:       ruleRef,
		before:        before,
		contextTokens: contextTokens,
		markerTokens:  e.Markers,
	})
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

type annotationParams struct {
	path          string
	tk            *token.Token
	message       string
	ruleRef       string
	before        *int
	contextTokens []*token.Token
	markerTokens  []*token.Token
}

// styled returns fn when color is enabled, or an identity function when disabled.
func (r *Renderer) styled(fn annotate.StyleFunc) annotate.StyleFunc {
	if r.noColor {
		return func(s string) string { return s }
	}
	return fn
}

func (r *Renderer) buildLabels(src []byte, p annotationParams) []annotate.Label {
	primary := annotate.Label{
		Span:   tokenSpan(src, p.tk),
		Marker: annotate.MarkerCaret,
		Text:   p.message,
		Before: p.before,
		Style: annotate.LabelStyle{
			Marker:    r.styled(annotate.FgRed),
			LabelText: r.styled(annotate.ComposeStyles(annotate.FgRed, annotate.Bold)),
		},
	}
	labels := []annotate.Label{primary}

	for _, ct := range p.contextTokens {
		if !isValidToken(ct) {
			continue
		}
		labels = append(labels, annotate.Label{
			Span:   tokenSpan(src, ct),
			Marker: annotate.MarkerNone,
		})
	}

	for _, mt := range p.markerTokens {
		if !isValidToken(mt) {
			continue
		}
		labels = append(labels, annotate.Label{
			Span:   tokenSpan(src, mt),
			Marker: annotate.MarkerCaret,
			Style: annotate.LabelStyle{
				Marker: r.styled(annotate.FgRed),
			},
		})
	}

	return labels
}

func (r *Renderer) formatHeader(path string, tk *token.Token) string {
	arrow := r.styled(annotate.ComposeStyles(annotate.FgCyan, annotate.Bold))("-->")
	displayPath := r.styled(annotate.Bold)(fmt.Sprintf("%s:%d:%d", path, tk.Position.Line, tk.Position.Column))
	return fmt.Sprintf("%s %s", arrow, displayPath)
}

func (r *Renderer) printAnnotatedError(p annotationParams) error {
	src, readErr := os.ReadFile(p.path)
	if readErr != nil {
		return fmt.Errorf("failed to read source file %s: %w", p.path, readErr)
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte(" \n")
	}

	labels := r.buildLabels(src, p)

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
		return fmt.Errorf("failed to render annotation for %s: %w", p.path, renderErr)
	}

	header := r.formatHeader(p.path, p.tk)
	if p.ruleRef != "" {
		fmt.Fprintf(os.Stderr, "%s\n%s%s\n\n", header, output, p.ruleRef)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n%s\n", header, output)
	}
	return nil
}
