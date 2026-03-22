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
type Renderer struct {
	noColor bool
}

// New creates a Renderer. When noColor is true, all styling is disabled.
func New(noColor bool) *Renderer {
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
	contextTokens := computeAncestors(e.Token)
	for _, ct := range e.ExtraContexts {
		if isValidToken(ct) {
			contextTokens = append(contextTokens, ct)
		}
	}
	sort.Slice(contextTokens, func(i, j int) bool {
		return contextTokens[i].Position.Offset < contextTokens[j].Position.Offset
	})

	return r.printAnnotatedError(annotationParams{
		path:          path,
		tk:            e.Token,
		message:       message,
		ruleRef:       ruleRef,
		contextTokens: contextTokens,
		markerTokens:  e.Markers,
	})
}

func isValidToken(tk *token.Token) bool {
	return tk != nil && tk.Position != nil
}

// isMappingKey reports whether tk is a mapping key (i.e., its Next token is ":").
func isMappingKey(tk *token.Token) bool {
	return tk.Next != nil && tk.Next.Type == token.MappingValueType
}

// computeAncestors walks the token chain backward from tk and collects
// structurally significant ancestor tokens (mapping keys and sequence entries)
// at strictly decreasing indentation levels.
func computeAncestors(tk *token.Token) []*token.Token {
	if !isValidToken(tk) {
		return nil
	}
	threshold := tk.Position.Column
	var ancestors []*token.Token
	for cur := tk.Prev; cur != nil; cur = cur.Prev {
		if cur.Position == nil {
			continue
		}
		col := cur.Position.Column
		if col >= threshold {
			continue
		}
		if cur.Type == token.SequenceEntryType || isMappingKey(cur) {
			ancestors = append(ancestors, cur)
			threshold = col
			if threshold <= 1 {
				break
			}
		}
	}
	// Reverse to root-first order
	for i, j := 0, len(ancestors)-1; i < j; i, j = i+1, j-1 {
		ancestors[i], ancestors[j] = ancestors[j], ancestors[i]
	}
	return ancestors
}

// tokenSpan converts a YAML token's position into an annotate.Span over src.
// It derives the byte offset from Line and Column rather than relying on
// Token.Offset, which can be incorrect in files containing YAML comments
// (a known goccy/go-yaml bug where each comment shifts subsequent Offsets by -1).
// The span is clamped to a single line and guaranteed to have non-zero length.
func tokenSpan(src []byte, tk *token.Token) annotate.Span {
	start := min(lineColumnOffset(src, tk.Position.Line, tk.Position.Column), len(src))
	if start < len(src) && (src[start] == '"' || src[start] == '\'') {
		start++
	}
	end := min(start+len(tk.Value), len(src))
	if idx := bytes.IndexByte(src[start:end], '\n'); idx >= 0 {
		end = start + idx
	}
	span := annotate.Span{Start: start, End: end}
	if span.End <= span.Start {
		span.End = span.Start + 1
	}
	// Clamp span to source length to prevent renderer errors on empty/null nodes.
	if span.End > len(src) {
		span.End = len(src)
	}
	if span.Start >= len(src) && len(src) > 0 {
		span.Start = len(src) - 1
		span.End = len(src)
	}
	// If span points at a newline or is at end of line, back up to find
	// the last non-whitespace character on the line. This ensures null/empty
	// tokens get a visible marker (^) on the relevant key.
	if span.Start < len(src) && (src[span.Start] == '\n' || src[span.Start] == '\r') {
		for span.Start > 0 && (src[span.Start-1] == ' ' || src[span.Start-1] == '\t' || src[span.Start-1] == '\n' || src[span.Start-1] == '\r') {
			span.Start--
		}
		span.End = span.Start + 1
		if span.Start > 0 {
			// Extend backward to cover the key name (find start of word).
			wordStart := span.Start
			for wordStart > 0 && src[wordStart-1] != ' ' && src[wordStart-1] != '\t' && src[wordStart-1] != '\n' {
				wordStart--
			}
			span.Start = wordStart
		}
	}
	return span
}

// lineColumnOffset returns the 0-based byte offset for a given 1-based line
// and 1-based column in src. This is used instead of Token.Offset to work
// around a goccy/go-yaml bug where comment tokens cause subsequent tokens'
// Offsets to drift by -1 per comment.
func lineColumnOffset(src []byte, line, column int) int {
	currentLine := 1
	for i, b := range src {
		if currentLine == line {
			return i + column - 1
		}
		if b == '\n' {
			currentLine++
		}
	}
	return len(src)
}

type annotationParams struct {
	path          string
	tk            *token.Token
	message       string
	ruleRef       string
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

func (r *Renderer) formatHeader(path string, src []byte, tk *token.Token) string {
	col := tk.Position.Column
	offset := min(lineColumnOffset(src, tk.Position.Line, tk.Position.Column), len(src))
	if offset < len(src) && (src[offset] == '"' || src[offset] == '\'') {
		col++
	}
	arrow := r.styled(annotate.ComposeStyles(annotate.FgCyan, annotate.Bold))("-->")
	displayPath := r.styled(annotate.Bold)(fmt.Sprintf("%s:%d:%d", path, tk.Position.Line, col))
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

	header := r.formatHeader(p.path, src, p.tk)
	if p.ruleRef != "" {
		fmt.Fprintf(os.Stderr, "%s\n%s%s\n\n", header, output, p.ruleRef)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n%s\n", header, output)
	}
	return nil
}
