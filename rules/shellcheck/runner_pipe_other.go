//go:build !unix

package shellcheck

import (
	"context"
	"errors"
)

// pipeInputSupported is false on platforms (e.g. Windows) that do not expose
// inherited descriptors as /dev/fd/N. RunBatch uses the temp-file path there.
const pipeInputSupported = false

// runBatchPipes is never called when pipeInputSupported is false; it exists only
// to satisfy the reference in RunBatch on these platforms.
func (r *execRunner) runBatchPipes(_ context.Context, _ string, _ []string) ([][]Comment, error) {
	return nil, errors.New("pipe input not supported on this platform")
}
