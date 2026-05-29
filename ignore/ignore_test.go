package ignore_test

import (
	"strings"
	"testing"

	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/ignore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		comment string
		wantIDs []string
		wantOK  bool
	}{
		{
			name:    "single rule",
			comment: " ghasec-ignore:unpinned-action",
			wantIDs: []string{"unpinned-action"},
			wantOK:  true,
		},
		{
			name:    "multiple rules",
			comment: " ghasec-ignore:unpinned-action,checkout-persist-credentials",
			wantIDs: []string{"unpinned-action", "checkout-persist-credentials"},
			wantOK:  true,
		},
		{
			name:    "all rules",
			comment: " ghasec-ignore",
			wantIDs: nil,
			wantOK:  true,
		},
		{
			name:    "spaces around commas",
			comment: " ghasec-ignore:foo , bar",
			wantIDs: []string{"foo", "bar"},
			wantOK:  true,
		},
		{
			name:    "empty rule IDs filtered",
			comment: " ghasec-ignore:,foo,",
			wantIDs: []string{"foo"},
			wantOK:  true,
		},
		{
			name:    "colon with no rule IDs treated as all-rules",
			comment: " ghasec-ignore:",
			wantIDs: nil,
			wantOK:  true,
		},
		{
			name:    "not a directive",
			comment: " some other comment",
			wantIDs: nil,
			wantOK:  false,
		},
		{
			name:    "ghasec-ignore mid-comment",
			comment: " v4  # ghasec-ignore:foo",
			wantIDs: nil,
			wantOK:  false,
		},
		{
			name:    "space before colon",
			comment: " ghasec-ignore :foo",
			wantIDs: nil,
			wantOK:  false,
		},
		{
			name:    "leading whitespace trimmed",
			comment: "  ghasec-ignore:foo",
			wantIDs: []string{"foo"},
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, ok := ignore.Parse(tt.comment)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantIDs, ids)
		})
	}
}

func TestCollect(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []struct {
			line    int
			ruleIDs []string
		}
	}{
		{
			name: "inline comment",
			yaml: "key: value # ghasec-ignore:foo",
			want: []struct {
				line    int
				ruleIDs []string
			}{
				{line: 1, ruleIDs: []string{"foo"}},
			},
		},
		{
			name: "previous-line comment",
			yaml: "# ghasec-ignore:foo\nkey: value",
			want: []struct {
				line    int
				ruleIDs []string
			}{
				{line: 2, ruleIDs: []string{"foo"}},
			},
		},
		{
			name: "no directives",
			yaml: "key: value # normal comment",
			want: nil,
		},
		{
			name: "multiple directives",
			yaml: "# ghasec-ignore:foo\na: 1\nb: 2 # ghasec-ignore:bar",
			want: []struct {
				line    int
				ruleIDs []string
			}{
				{line: 2, ruleIDs: []string{"foo"}},
				{line: 3, ruleIDs: []string{"bar"}},
			},
		},
		{
			name: "all-rules inline",
			yaml: "key: value # ghasec-ignore",
			want: []struct {
				line    int
				ruleIDs []string
			}{
				{line: 1, ruleIDs: nil},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := yamlparser.ParseBytes([]byte(tt.yaml), 0)
			require.NoError(t, err)
			require.NotEmpty(t, f.Docs)

			tk := f.Docs[0].Body.GetToken()
			for tk.Prev != nil {
				tk = tk.Prev
			}

			directives := ignore.Collect(tk)

			if tt.want == nil {
				assert.Empty(t, directives)
				return
			}

			require.Len(t, directives, len(tt.want))
			for i, w := range tt.want {
				assert.Equal(t, w.line, directives[i].Line, "directive %d line", i)
				assert.Equal(t, w.ruleIDs, directives[i].RuleIDs, "directive %d ruleIDs", i)
				assert.NotNil(t, directives[i].Token, "directive %d token", i)
			}
		})
	}
}

// substringAt returns the source substring of length n starting at the given
// 1-based line and column. The renderer maps a token's Position to the source
// the same way (line + column), so this checks that a synthetic token's Column
// actually lands on the text its Value claims to mark.
func substringAt(t *testing.T, src string, line, col, n int) string {
	t.Helper()
	lines := strings.Split(src, "\n")
	require.GreaterOrEqual(t, line, 1)
	require.LessOrEqual(t, line, len(lines))
	ln := lines[line-1]
	start := col - 1
	require.GreaterOrEqual(t, start, 0)
	require.LessOrEqual(t, start+n, len(ln), "token span overruns source line %q", ln)
	return ln[start : start+n]
}

// TestKeywordTokenColumn verifies the all-rules directive's synthetic token
// points exactly at the "ghasec-ignore" keyword in the source, including when
// the comment follows a block scalar header (`|`/`>`), where go-yaml shifts the
// comment token's column.
func TestKeywordTokenColumn(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "normal inline", yaml: "a: b # ghasec-ignore\n"},
		{name: "standalone", yaml: "# ghasec-ignore\na: b\n"},
		{name: "after literal header", yaml: "steps:\n  - run: | # ghasec-ignore\n      echo x\n"},
		{name: "after folded header", yaml: "steps:\n  - run: > # ghasec-ignore\n      echo x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := yamlparser.ParseBytes([]byte(tt.yaml), 0)
			require.NoError(t, err)
			tk := f.Docs[0].Body.GetToken()
			for tk.Prev != nil {
				tk = tk.Prev
			}
			directives := ignore.Collect(tk)
			require.Len(t, directives, 1)

			kw := directives[0].KeywordToken()
			require.Equal(t, "ghasec-ignore", kw.Value)
			got := substringAt(t, tt.yaml, kw.Position.Line, kw.Position.Column, len(kw.Value))
			assert.Equal(t, "ghasec-ignore", got, "caret should underline the keyword")
		})
	}
}

// TestRuleIDTokenColumn verifies a per-rule directive's synthetic token points
// exactly at the rule ID in the source, across the same comment placements.
func TestRuleIDTokenColumn(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "normal inline", yaml: "a: b # ghasec-ignore:script-injection\n"},
		{name: "standalone", yaml: "# ghasec-ignore:script-injection\na: b\n"},
		{name: "after literal header", yaml: "steps:\n  - run: | # ghasec-ignore:script-injection\n      echo x\n"},
		{name: "after folded header", yaml: "steps:\n  - run: > # ghasec-ignore:script-injection\n      echo x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := yamlparser.ParseBytes([]byte(tt.yaml), 0)
			require.NoError(t, err)
			tk := f.Docs[0].Body.GetToken()
			for tk.Prev != nil {
				tk = tk.Prev
			}
			directives := ignore.Collect(tk)
			require.Len(t, directives, 1)

			rt := directives[0].RuleIDToken("script-injection")
			require.Equal(t, "script-injection", rt.Value)
			got := substringAt(t, tt.yaml, rt.Position.Line, rt.Position.Column, len(rt.Value))
			assert.Equal(t, "script-injection", got, "caret should underline the rule ID")
		})
	}
}

// TestCollectEndLine verifies that a directive targeting a block scalar's start
// line has its EndLine extended to cover the full block, while a directive on a
// non-block line keeps EndLine == Line.
func TestCollectEndLine(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantLine int
		wantEnd  int
	}{
		{
			name:     "non-block inline keeps EndLine == Line",
			yaml:     "key: value # ghasec-ignore:foo",
			wantLine: 1,
			wantEnd:  1,
		},
		{
			name:     "previous-line comment on plain value keeps EndLine == Line",
			yaml:     "# ghasec-ignore:foo\nkey: value",
			wantLine: 2,
			wantEnd:  2,
		},
		{
			name:     "inline on literal block extends to last content line",
			yaml:     "steps:\n  - run: | # ghasec-ignore:foo\n      echo a\n      echo b\n    name: x\n",
			wantLine: 2,
			wantEnd:  4,
		},
		{
			name:     "previous-line before literal block extends to last content line",
			yaml:     "steps:\n  # ghasec-ignore:foo\n  - run: |\n      echo a\n      echo b\n    name: x\n",
			wantLine: 3,
			wantEnd:  5,
		},
		{
			name:     "inline on folded block extends to last content line",
			yaml:     "steps:\n  - run: >- # ghasec-ignore:foo\n      echo a\n      echo b\n    name: x\n",
			wantLine: 2,
			wantEnd:  4,
		},
		{
			name:     "literal block last in file (single content line)",
			yaml:     "steps:\n  - run: | # ghasec-ignore:foo\n      echo a\n",
			wantLine: 2,
			wantEnd:  3,
		},
		{
			name:     "literal block last in file (multiple content lines)",
			yaml:     "steps:\n  - run: | # ghasec-ignore:foo\n      echo a\n      echo b\n      echo c\n",
			wantLine: 2,
			wantEnd:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := yamlparser.ParseBytes([]byte(tt.yaml), 0)
			require.NoError(t, err)
			require.NotEmpty(t, f.Docs)

			tk := f.Docs[0].Body.GetToken()
			for tk.Prev != nil {
				tk = tk.Prev
			}

			directives := ignore.Collect(tk)
			require.Len(t, directives, 1)
			assert.Equal(t, tt.wantLine, directives[0].Line, "Line")
			assert.Equal(t, tt.wantEnd, directives[0].EndLine, "EndLine")
		})
	}
}
