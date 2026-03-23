// Package cron validates 5-field POSIX cron expressions as used by GitHub Actions.
package cron

import (
	"fmt"
	"strconv"
	"strings"
)

// fieldSpec defines the valid range for a cron field.
type fieldSpec struct {
	name string
	min  int
	max  int
}

var fields = [5]fieldSpec{
	{"minute", 0, 59},
	{"hour", 0, 23},
	{"day-of-month", 1, 31},
	{"month", 1, 12},
	{"day-of-week", 0, 6},
}

// Validate checks whether expr is a valid 5-field POSIX cron expression.
// Returns a human-readable error message if invalid, or "" if valid.
func Validate(expr string) string {
	expr = strings.TrimSpace(expr)
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return fmt.Sprintf("expected 5 fields, but got %d", len(parts))
	}
	for i, part := range parts {
		if err := validateField(part, fields[i]); err != "" {
			return fmt.Sprintf("invalid %s field %q: %s", fields[i].name, part, err)
		}
	}
	return ""
}

// validateField validates a single cron field (e.g., "0,15,30,45" or "*/5" or "1-5").
func validateField(field string, spec fieldSpec) string {
	entries := strings.Split(field, ",")
	for _, entry := range entries {
		if entry == "" {
			return "empty entry"
		}
		if err := validateEntry(entry, spec); err != "" {
			return err
		}
	}
	return ""
}

// validateEntry validates a single entry within a comma-separated field.
func validateEntry(entry string, spec fieldSpec) string {
	// Handle step values: */N or N-M/N or N/N
	if idx := strings.Index(entry, "/"); idx != -1 {
		base := entry[:idx]
		step := entry[idx+1:]
		stepVal, err := strconv.Atoi(step)
		if err != nil {
			return fmt.Sprintf("invalid step value %q", step)
		}
		if stepVal <= 0 {
			return fmt.Sprintf("step value must be > 0, but got %d", stepVal)
		}
		return validateRangeOrWildcard(base, spec)
	}

	// Handle range: N-M
	if idx := strings.Index(entry, "-"); idx != -1 {
		return validateRange(entry, spec)
	}

	// Handle wildcard
	if entry == "*" {
		return ""
	}

	// Handle single number
	return validateNumber(entry, spec)
}

// validateRangeOrWildcard validates the base of a step expression (before /).
func validateRangeOrWildcard(base string, spec fieldSpec) string {
	if base == "*" {
		return ""
	}
	if strings.Contains(base, "-") {
		return validateRange(base, spec)
	}
	return validateNumber(base, spec)
}

// validateRange validates a range expression like "N-M".
func validateRange(expr string, spec fieldSpec) string {
	parts := strings.SplitN(expr, "-", 2)
	if len(parts) != 2 {
		return fmt.Sprintf("invalid range %q", expr)
	}
	min, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Sprintf("invalid range start %q", parts[0])
	}
	max, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Sprintf("invalid range end %q", parts[1])
	}
	if min < spec.min || min > spec.max {
		return fmt.Sprintf("value %d out of range %d-%d", min, spec.min, spec.max)
	}
	if max < spec.min || max > spec.max {
		return fmt.Sprintf("value %d out of range %d-%d", max, spec.min, spec.max)
	}
	if min > max {
		return fmt.Sprintf("range start %d must not be greater than end %d", min, max)
	}
	return ""
}

// validateNumber validates a single numeric value.
func validateNumber(s string, spec fieldSpec) string {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Sprintf("invalid value %q", s)
	}
	if n < spec.min || n > spec.max {
		return fmt.Sprintf("value %d out of range %d-%d", n, spec.min, spec.max)
	}
	return ""
}
