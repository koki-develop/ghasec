package expression

import "strings"

// Span represents a single ${{ ... }} expression found in a string value.
type Span struct {
	Start int
	End   int
	Inner string
}

// Error represents a syntax error at a specific offset within an expression.
type Error struct {
	Offset  int
	Message string
}

// ExtractExpressions finds all ${{ ... }} expression spans in the given value.
// It returns the spans and any extraction-level errors (e.g. unterminated expressions).
func ExtractExpressions(value string) ([]Span, []Error) {
	var spans []Span
	var errs []Error
	pos := 0
	for {
		idx := strings.Index(value[pos:], "${{")
		if idx == -1 {
			break
		}
		start := pos + idx
		innerStart := start + 3
		end := findClosingBraces(value, innerStart)
		if end == -1 {
			errs = append(errs, Error{
				Offset:  start,
				Message: "unterminated expression: missing closing '}}'",
			})
			break
		}
		spans = append(spans, Span{
			Start: start,
			End:   end + 2,
			Inner: value[innerStart:end],
		})
		pos = end + 2
	}
	return spans, errs
}

func findClosingBraces(value string, from int) int {
	pos := from
	inString := false
	for pos < len(value) {
		ch := value[pos]
		if inString {
			if ch == '\'' {
				if pos+1 < len(value) && value[pos+1] == '\'' {
					pos += 2
					continue
				}
				inString = false
			}
			pos++
			continue
		}
		if ch == '\'' {
			inString = true
			pos++
			continue
		}
		if ch == '}' && pos+1 < len(value) && value[pos+1] == '}' {
			return pos
		}
		pos++
	}
	return -1
}

// Parse parses a GitHub Actions expression (the content between ${{ and }}).
// It returns any syntax errors found. A nil return means the expression is valid.
func Parse(input string) []Error {
	p := newParser(input)
	errs := p.parse()
	if len(errs) == 0 {
		return nil
	}
	return errs
}
