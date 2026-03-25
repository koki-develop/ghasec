package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	barFilled    = "\u2588" // █
	barEmpty     = "\u2591" // ░
	defaultWidth = 80
	minBarWidth  = 10
	maxBarWidth  = 40
	tickInterval = 100 * time.Millisecond

	ansiReset = "\033[0m"
	ansiCyan  = "\033[36m"
	ansiDim   = "\033[2m"
)

var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// Status represents the current progress of rule execution.
type Status struct {
	Completed int // rule executions completed across all files
	Total     int // total expected rule executions
}

// Progress renders a single-line progress bar to the given writer.
// All methods are safe for concurrent use.
type Progress struct {
	mu      sync.Mutex
	w       io.Writer
	fd      int
	noColor bool

	lastWidth int
	frame     int
	status    Status
	stop      chan struct{}
	stopOnce  sync.Once
	cleared   bool
}

// New creates a Progress that writes to w and starts a background
// ticker for spinner animation and terminal width refresh. fd is the
// file descriptor used to query terminal width.
func New(w io.Writer, fd int, noColor bool) *Progress {
	p := &Progress{w: w, fd: fd, noColor: noColor, stop: make(chan struct{})}
	go p.tick()
	return p
}

// newWithWidth creates a Progress with a fixed terminal width (for testing).
// No background ticker is started.
func newWithWidth(w io.Writer, termWidth int, noColor bool) *Progress {
	return &Progress{w: w, fd: -1, lastWidth: termWidth, noColor: noColor}
}

func (p *Progress) tick() {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.redraw()
		}
	}
}

func (p *Progress) termWidth() int {
	if p.fd >= 0 {
		w, _, err := term.GetSize(p.fd)
		if err == nil && w > 0 {
			return w
		}
	}
	if p.lastWidth > 0 {
		return p.lastWidth
	}
	return defaultWidth
}

func (p *Progress) colorize(code, s string) string {
	if p.noColor {
		return s
	}
	return code + s + ansiReset
}

// Update stores the latest status.
func (p *Progress) Update(status Status) {
	p.mu.Lock()
	p.status = status
	p.mu.Unlock()
}

func (p *Progress) redraw() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cleared {
		return
	}

	tw := p.termWidth()
	p.lastWidth = tw

	pct := 0
	if p.status.Total > 0 {
		pct = p.status.Completed * 100 / p.status.Total
	}
	if pct > 100 {
		pct = 100
	}

	spinnerChar := string(spinnerFrames[p.frame%len(spinnerFrames)])
	p.frame++

	pctStr := fmt.Sprintf(" %d%%", pct)

	// Compute bar width from plain-text widths (no ANSI in the calculation)
	// Layout: "<spinner> Checking... [<bar>] <pct>"
	plainPrefix := spinnerChar + " Checking... ["
	plainClosing := "]"
	barWidth := min(max(tw-utf8.RuneCountInString(plainPrefix)-len(plainClosing)-len(pctStr), minBarWidth), maxBarWidth)

	filled := barWidth * pct / 100
	empty := barWidth - filled

	// Build line with colors
	line := p.colorize(ansiCyan, spinnerChar) +
		" Checking... [" +
		strings.Repeat(barFilled, filled) +
		p.colorize(ansiDim, strings.Repeat(barEmpty, empty)) +
		"]" +
		pctStr

	// Truncate to terminal width by rune count, but skip ANSI escape sequences
	// since they are zero-width on the terminal.
	line = truncateVisible(line, tw)

	_, _ = fmt.Fprintf(p.w, "\r%s", line)
}

// truncateVisible truncates s so that at most maxVisible non-ANSI runes remain.
func truncateVisible(s string, maxVisible int) string {
	var b strings.Builder
	visible := 0
	inEscape := false
	for _, r := range s {
		if r == '\033' {
			inEscape = true
		}
		if inEscape {
			b.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		if visible >= maxVisible {
			break
		}
		b.WriteRune(r)
		visible++
	}
	return b.String()
}

// Clear stops the background ticker and removes the progress bar line.
// Safe to call multiple times.
func (p *Progress) Clear() {
	p.stopOnce.Do(func() {
		if p.stop != nil {
			close(p.stop)
		}
	})

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cleared {
		return
	}
	p.cleared = true

	tw := p.termWidth()
	_, _ = fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", tw))
}
