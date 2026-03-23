package cron

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		// Valid expressions
		{"simple", "0 5 * * 1", false},
		{"every minute", "* * * * *", false},
		{"complex", "0,30 9-17 * 1-6 1-5", false},
		{"step all", "*/5 * * * *", false},
		{"step range", "0-30/5 * * * *", false},
		{"boundary min", "0 0 1 1 0", false},
		{"boundary max", "59 23 31 12 6", false},
		{"extra whitespace", "  0  5  *  *  1  ", false},
		{"step with base number", "5/15 * * * *", false},

		// Invalid expressions
		{"too few fields", "0 5 *", true},
		{"too many fields", "0 5 * * * *", true},
		{"empty string", "", true},
		{"nonsense", "not a cron", true},
		{"minute out of range", "60 * * * *", true},
		{"hour out of range", "* 24 * * *", true},
		{"day out of range zero", "* * 0 * *", true},
		{"day out of range 32", "* * 32 * *", true},
		{"month out of range zero", "* * * 0 *", true},
		{"month out of range 13", "* * * 13 *", true},
		{"dow out of range", "* * * * 7", true},
		{"step value 0", "*/0 * * * *", true},
		{"range min > max", "5-3 * * * *", true},
		{"negative step", "*/-1 * * * *", true},
		{"empty comma entry", "0, * * * *", true},
		{"non-numeric", "abc * * * *", true},
		{"non-numeric step", "*/abc * * * *", true},
		{"non-numeric range start", "abc-5 * * * *", true},
		{"non-numeric range end", "1-abc * * * *", true},
		{"step with out-of-range base", "60/5 * * * *", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Validate(tt.expr)
			if tt.wantErr {
				assert.NotEmpty(t, result, "expected error for %q", tt.expr)
			} else {
				assert.Empty(t, result, "expected no error for %q, got %q", tt.expr, result)
			}
		})
	}
}
