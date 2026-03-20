package ignore_test

import (
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
