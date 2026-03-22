package rules

import (
	"sort"

	"github.com/goccy/go-yaml/token"
)

type ErrorKind int

const (
	KindUnknownKey ErrorKind = iota
	KindRequiredKey
	KindTypeMismatch
	KindInvalidEnum
	KindMinItems // sequence/mapping has too few items
)

type ValidationError struct {
	Kind    ErrorKind
	Path    string   // dotted path (e.g. "jobs.build.permissions")
	Parent  string   // parent key name for context-rich messages (e.g. "permissions", "branding")
	Context string   // domain term for the error (e.g. "scope", "color", "event")
	Key     string   // target key name or value
	Got     string   // actual value/type
	Allowed []string // allowed values (for enum, etc.)
	Token   *token.Token
}

// SortRequiredFirst reorders errors so that KindRequiredKey errors at the same
// position come before other errors.
func SortRequiredFirst(errs []ValidationError) []ValidationError {
	sort.SliceStable(errs, func(i, j int) bool {
		posI := errs[i].Token.Position.Offset
		posJ := errs[j].Token.Position.Offset
		if posI != posJ {
			return posI < posJ
		}
		iReq := errs[i].Kind == KindRequiredKey
		jReq := errs[j].Kind == KindRequiredKey
		if iReq != jReq {
			return iReq
		}
		return false
	})
	return errs
}

// Dedup removes duplicate ValidationErrors (same token offset + kind + key + got).
func Dedup(errs []ValidationError) []ValidationError {
	type dedupKey struct {
		offset int
		kind   ErrorKind
		key    string
		got    string
	}
	seen := make(map[dedupKey]bool)
	var result []ValidationError
	for _, e := range errs {
		dk := dedupKey{
			offset: e.Token.Position.Offset,
			kind:   e.Kind,
			key:    e.Key,
			got:    e.Got,
		}
		if seen[dk] {
			continue
		}
		seen[dk] = true
		result = append(result, e)
	}
	return result
}
