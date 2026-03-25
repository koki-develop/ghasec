package progress

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func updateAndRedraw(p *Progress, s Status) {
	p.Update(s)
	p.redraw()
}

func TestProgress_Redraw_ZeroPercent(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	updateAndRedraw(p, Status{Completed: 0, Total: 100})
	out := buf.String()
	assert.Contains(t, out, "0%")
	assert.Contains(t, out, "Checking...")
	assert.True(t, strings.HasPrefix(out, "\r"))
}

func TestProgress_Redraw_FiftyPercent(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	updateAndRedraw(p, Status{Completed: 50, Total: 100})
	out := buf.String()
	assert.Contains(t, out, "50%")
}

func TestProgress_Redraw_HundredPercent(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	updateAndRedraw(p, Status{Completed: 100, Total: 100})
	out := buf.String()
	assert.Contains(t, out, "100%")
}

func TestProgress_Clear(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 40, true)
	updateAndRedraw(p, Status{Completed: 50, Total: 100})
	buf.Reset()
	p.Clear()
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "\r"))
	trimmed := strings.TrimRight(out, " \r")
	assert.Empty(t, strings.TrimLeft(trimmed, "\r "))
}

func TestProgress_Redraw_TotalZero(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	updateAndRedraw(p, Status{Completed: 0, Total: 0})
	out := buf.String()
	assert.Contains(t, out, "0%")
}

func TestProgress_Redraw_BarContainsFillAndEmpty(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	updateAndRedraw(p, Status{Completed: 25, Total: 50})
	out := buf.String()
	require.Contains(t, out, barFilled)
	require.Contains(t, out, barEmpty)
}

func TestProgress_Redraw_OverHundredPercentClamped(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	updateAndRedraw(p, Status{Completed: 120, Total: 100})
	out := buf.String()
	assert.Contains(t, out, "100%")
	assert.NotContains(t, out, barEmpty)
}

func TestProgress_Redraw_NarrowTerminal_MinBarWidth(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 20, true)
	updateAndRedraw(p, Status{Completed: 10, Total: 50})
	out := buf.String()
	runes := []rune(out)
	assert.LessOrEqual(t, len(runes)-1, 20)
}

func TestProgress_Redraw_RuneTruncation(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 15, true)
	updateAndRedraw(p, Status{Completed: 1, Total: 2})
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "\r"))
	content := strings.TrimPrefix(out, "\r")
	assert.LessOrEqual(t, len([]rune(content)), 15)
}

func TestProgress_Spinner_Advances(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	p.redraw()
	first := buf.String()
	buf.Reset()
	p.redraw()
	second := buf.String()
	firstRunes := []rune(first)
	secondRunes := []rune(second)
	assert.NotEqual(t, firstRunes[1], secondRunes[1])
}

func TestProgress_MaxBarWidth(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 200, true)
	updateAndRedraw(p, Status{Completed: 50, Total: 100})
	out := buf.String()
	filledCount := strings.Count(out, barFilled)
	emptyCount := strings.Count(out, barEmpty)
	assert.Equal(t, maxBarWidth, filledCount+emptyCount)
}

func TestProgress_Update_StoresStatus(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true)
	p.Update(Status{Completed: 42, Total: 100})
	assert.Empty(t, buf.String())
	p.redraw()
	out := buf.String()
	assert.Contains(t, out, "42%")
}

func TestProgress_Color_Enabled(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, false) // color enabled
	updateAndRedraw(p, Status{Completed: 50, Total: 100})
	out := buf.String()
	// Should contain ANSI escape codes
	assert.Contains(t, out, "\033[36m") // cyan for spinner
	assert.Contains(t, out, "\033[2m")  // dim for empty bar
	assert.Contains(t, out, "\033[0m")  // reset
}

func TestProgress_Color_Disabled(t *testing.T) {
	var buf bytes.Buffer
	p := newWithWidth(&buf, 80, true) // color disabled
	updateAndRedraw(p, Status{Completed: 50, Total: 100})
	out := buf.String()
	// Should not contain ANSI escape codes
	assert.NotContains(t, out, "\033[")
}

func TestProgress_TruncateVisible_WithANSI(t *testing.T) {
	// A string with ANSI codes should truncate based on visible characters only
	s := "\033[36mHello\033[0m World"
	result := truncateVisible(s, 8)
	// "Hello Wo" = 8 visible chars, ANSI codes preserved
	assert.Contains(t, result, "\033[36m")
	assert.Contains(t, result, "Hello")
	// Count visible chars
	visible := 0
	inEscape := false
	for _, r := range result {
		if r == '\033' {
			inEscape = true
		}
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		visible++
	}
	assert.LessOrEqual(t, visible, 8)
}
