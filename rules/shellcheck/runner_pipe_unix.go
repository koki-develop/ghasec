//go:build unix

package shellcheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// pipeInputSupported reports that the /dev/fd pipe transport is usable on this
// platform. Unix exposes inherited descriptors as /dev/fd/N, which shellcheck can
// open as input files.
const pipeInputSupported = true

// init raises the soft open-file limit toward the hard limit. runBatchPipes feeds
// each script through its own pipe (two descriptors), so a batch of hundreds of
// scripts — times several batches running concurrently — can need well over the
// default soft limit of 256. Raising it up front avoids "too many open files".
func init() {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	want := uint64(8192)
	if lim.Max != 0 && want > lim.Max {
		want = lim.Max
	}
	if lim.Cur < want {
		lim.Cur = want
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
}

// runBatchPipes lints scripts by streaming each through its own pipe, exposed to
// the shellcheck child as /dev/fd/N (ExtraFiles entry i becomes child fd 3+i).
// This avoids writing hundreds of small temp files to disk per run — the
// open/write/unlink syscalls and filesystem-metadata churn were a measurable
// share of the batch cost and also evicted directory-cache pages the concurrent
// action walk depends on. Pipes are in-memory; shellcheck's findings are
// byte-identical to the temp-file path. Scripts are small (smaller than the pipe
// buffer), so each can be written and closed without a reader, so there is no
// writer/reader deadlock.
func (r *execRunner) runBatchPipes(ctx context.Context, shell string, scripts []string) ([][]Comment, error) {
	idxByFd := make(map[string]int, len(scripts))
	args := append(append([]string{}, scArgs...), "-s", shell)
	readEnds := make([]*os.File, 0, len(scripts))
	writeEnds := make([]*os.File, 0, len(scripts))
	closeReads := func() {
		for _, rd := range readEnds {
			_ = rd.Close()
		}
	}
	for i, s := range scripts {
		rd, wr, perr := os.Pipe()
		if perr != nil {
			closeReads()
			for _, w := range writeEnds {
				_ = w.Close()
			}
			return nil, perr
		}
		readEnds = append(readEnds, rd)
		writeEnds = append(writeEnds, wr)
		fd := fmt.Sprintf("/dev/fd/%d", 3+i)
		idxByFd[fd] = i
		args = append(args, fd)
		go func(w *os.File, s string) {
			_, _ = io.WriteString(w, s)
			_ = w.Close()
		}(wr, s)
	}
	defer closeReads()

	cmd := exec.CommandContext(ctx, r.path, args...)
	cmd.ExtraFiles = readEnds
	comments, err := runCmd(cmd)
	if err != nil {
		return nil, err
	}

	out := make([][]Comment, len(scripts))
	for _, c := range comments {
		if idx, ok := idxByFd[c.File]; ok {
			out[idx] = append(out[idx], c)
		}
	}
	return out, nil
}
