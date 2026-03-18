package git

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRef_IsFullSHA(t *testing.T) {
	tests := []struct {
		name string
		ref  Ref
		want bool
	}{
		{"valid 40-char lowercase hex", Ref("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), true},
		{"short sha", Ref("abc0123"), false},
		{"tag name", Ref("v1.0.0"), false},
		{"empty", Ref(""), false},
		{"uppercase hex", Ref("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), false},
		{"39 chars", Ref("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), false},
		{"41 chars", Ref("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ref.IsFullSHA())
		})
	}
}

func TestRef_IsValid(t *testing.T) {
	valid := []struct {
		name string
		ref  Ref
	}{
		{"simple tag", Ref("v4")},
		{"semver tag", Ref("v5.4.0")},
		{"slash-separated", Ref("release/v1.0")},
		{"alphanumeric", Ref("beta1")},
		{"hyphens and dots", Ref("my-tag-1.0")},
		{"underscores", Ref("my_tag")},
	}

	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			assert.True(t, tt.ref.IsValid(), "expected %q to be valid", tt.ref)
		})
	}

	invalid := []struct {
		name string
		ref  Ref
	}{
		{"empty", Ref("")},
		{"at sign", Ref("@")},
		{"space", Ref("some tag")},
		{"tilde", Ref("v1~1")},
		{"caret", Ref("v1^2")},
		{"colon", Ref("v1:2")},
		{"backslash", Ref("v1\\2")},
		{"question mark", Ref("v1?")},
		{"asterisk", Ref("v1*")},
		{"bracket", Ref("v1[0]")},
		{"double dot", Ref("v1..2")},
		{"at-brace", Ref("v1@{0}")},
		{"trailing dot", Ref("v1.")},
		{"trailing .lock", Ref("v1.lock")},
		{"leading dash", Ref("-v1")},
		{"leading dot", Ref(".v1")},
		{"control char", Ref("v1\x00")},
		{"leading slash", Ref("/v1")},
		{"trailing slash", Ref("v1/")},
		{"double slash", Ref("v1//v2")},
		{"dot component", Ref("v1/.hidden")},
	}

	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			assert.False(t, tt.ref.IsValid(), "expected %q to be invalid", tt.ref)
		})
	}
}
