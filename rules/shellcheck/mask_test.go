package shellcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskExpressions_Basic(t *testing.T) {
	masked, regions, _ := maskExpressions("echo ${{ x }}")
	// "${{ x }}" is 8 bytes -> "${GGGGG}" is 8 bytes.
	assert.Equal(t, "echo ${GGGGG}", masked)
	assert.Equal(t, len("echo ${{ x }}"), len(masked), "byte length must be preserved")
	require.Len(t, regions, 1)
	// "${GGGGG}" occupies columns 6..13 inclusive -> colEnd exclusive 14.
	assert.Equal(t, maskRegion{line: 1, colStart: 6, colEnd: 14}, regions[0])
}

func TestMaskExpressions_ProducesVariableForm(t *testing.T) {
	masked, _, _ := maskExpressions("TARGET=${{ inputs.target }}")
	// Must be a ${...} variable expansion (dynamic), not a bare constant.
	assert.Contains(t, masked, "${")
	assert.Contains(t, masked, "}")
	assert.Equal(t, len("TARGET=${{ inputs.target }}"), len(masked))
}

func TestMaskExpressions_Multibyte(t *testing.T) {
	src := "echo ${{ inputs.メッセージ }}"
	masked, _, _ := maskExpressions(src)
	// Byte length preserved even with multibyte content inside the expression.
	assert.Equal(t, len(src), len(masked))
}

func TestMaskExpressions_Multiple(t *testing.T) {
	src := "deploy ${{ a }} to ${{ bb }}"
	masked, regions, _ := maskExpressions(src)
	assert.Equal(t, len(src), len(masked))
	require.Len(t, regions, 2)
	// Both on line 1, distinct column spans.
	assert.Equal(t, 1, regions[0].line)
	assert.Equal(t, 1, regions[1].line)
	assert.Less(t, regions[0].colEnd, regions[1].colStart)
}

func TestMaskExpressions_CRLFPreserved(t *testing.T) {
	src := "echo ${{ x }}\r\necho done"
	masked, _, _ := maskExpressions(src)
	assert.Contains(t, masked, "\r\n")
	assert.Equal(t, len(src), len(masked))
}

func TestMaskExpressions_NoExpressions(t *testing.T) {
	src := "echo $x"
	masked, regions, _ := maskExpressions(src)
	assert.Equal(t, src, masked)
	assert.Empty(t, regions)
}

func TestMaskExpressions_MultiLineScript(t *testing.T) {
	src := "echo \"${{ a }}\"\ngit checkout ${{ b }}"
	masked, regions, _ := maskExpressions(src)
	assert.Equal(t, len(src), len(masked))
	require.Len(t, regions, 2)
	assert.Equal(t, 1, regions[0].line)
	assert.Equal(t, 2, regions[1].line)
}

func TestMaskExpressions_MalformedReportsError(t *testing.T) {
	_, _, malformed := maskExpressions("echo ${{ hello")
	assert.True(t, malformed, "unterminated ${{ should report malformed")

	_, _, ok := maskExpressions("echo ${{ valid }}")
	assert.False(t, ok, "well-formed expression must not report malformed")

	_, _, none := maskExpressions("echo plain")
	assert.False(t, none)
}

func TestIsInsideMask(t *testing.T) {
	regions := []maskRegion{{line: 7, colStart: 14, colEnd: 40}}

	// Fully inside (e.g. SC2086 on the placeholder itself): drop.
	assert.True(t, isInsideMask(regions, 7, 14, 40))
	assert.True(t, isInsideMask(regions, 7, 16, 38))

	// Column outside the mask: keep.
	assert.False(t, isInsideMask(regions, 7, 1, 5))
	// Partial overlap (starts inside, ends past): keep.
	assert.False(t, isInsideMask(regions, 7, 20, 45))
	// Different line: keep.
	assert.False(t, isInsideMask(regions, 8, 14, 40))
}
