package update

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSemver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input   string
		want    semver
		wantErr bool
	}{
		{input: "1.2.3", want: semver{1, 2, 3}},
		{input: "v1.2.3", want: semver{1, 2, 3}},
		{input: "0.5.0", want: semver{0, 5, 0}},
		{input: "v0.0.1", want: semver{0, 0, 1}},
		{input: "10.20.30", want: semver{10, 20, 30}},
		{input: "dev", wantErr: true},
		{input: "(devel)", wantErr: true},
		{input: "", wantErr: true},
		{input: "v1.2", wantErr: true},
		{input: "v1.2.3.4", wantErr: true},
		{input: "v1.2.x", wantErr: true},
		{input: "v-1.2.3", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got, err := parseSemver(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSemverLessThan(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want bool
	}{
		{a: "0.5.0", b: "0.6.0", want: true},
		{a: "0.6.0", b: "0.5.0", want: false},
		{a: "0.5.0", b: "0.5.0", want: false},
		{a: "1.0.0", b: "2.0.0", want: true},
		{a: "0.5.0", b: "0.5.1", want: true},
		{a: "0.9.9", b: "1.0.0", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_<_"+tt.b, func(t *testing.T) {
			t.Parallel()
			a, err := parseSemver(tt.a)
			require.NoError(t, err)
			b, err := parseSemver(tt.b)
			require.NoError(t, err)
			assert.Equal(t, tt.want, a.lessThan(b))
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{input: "v1.2.3", want: "1.2.3"},
		{input: "1.2.3", want: "1.2.3"},
		{input: "v0.5.0", want: "0.5.0"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			sv, err := parseSemver(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, sv.String())
		})
	}
}
