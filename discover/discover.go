package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Result holds discovered file paths grouped by type.
type Result struct {
	Workflows []string
	Actions   []string
}

// Discover returns workflow and action file paths under baseDir.
// Workflows: baseDir/.github/workflows/*.yml|yaml
// Actions: any action.yml|action.yaml found recursively, excluding .git/ and node_modules/.
// Files that appear in both sets (e.g. .github/workflows/action.yml) are kept only in Workflows.
func Discover(baseDir string) (Result, error) {
	workflows, workflowSet, err := GlobWorkflows(baseDir)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Workflows: workflows,
		Actions:   FindActions(baseDir, workflowSet),
	}, nil
}

// GlobWorkflows returns the sorted workflow file paths under
// baseDir/.github/workflows/ along with the set of their absolute paths (used to
// dedupe against the recursive action search). It is fast — a couple of globs —
// so callers can begin processing workflows while the (much slower) recursive
// action walk runs concurrently in FindActions.
func GlobWorkflows(baseDir string) (workflows []string, workflowSet map[string]struct{}, err error) {
	workflowSet = map[string]struct{}{}
	for _, ext := range []string{"*.yml", "*.yaml"} {
		pattern := filepath.Join(baseDir, ".github", "workflows", ext)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, nil, err
		}
		for _, m := range matches {
			abs, err := filepath.Abs(m)
			if err != nil {
				return nil, nil, err
			}
			workflowSet[abs] = struct{}{}
		}
		workflows = append(workflows, matches...)
	}
	sort.Strings(workflows)
	return workflows, workflowSet, nil
}

// FindActions returns the sorted action.yml/action.yaml file paths found
// recursively under baseDir, excluding .git/ and node_modules/ and any path
// already in workflowSet or inside .github/workflows/.
//
// It uses a concurrent recursive walk driven by a fixed worker pool sharing an
// explicit directory stack. Directory reads are syscall-bound, so reading many
// directories at once overlaps them across cores and beats a serial WalkDir on
// large monorepos. A goroutine-per-directory variant was simpler but spawned one
// goroutine per directory (tens of thousands on a big repo), and the cold-start
// cost of allocating that many goroutine stacks dominated the walk. A fixed pool
// keeps the parallelism without that allocation churn. The final result is
// sorted, so the nondeterministic traversal order does not affect output.
func FindActions(baseDir string, workflowSet map[string]struct{}) []string {
	actions := walkActions(baseDir, workflowSet)
	sort.Strings(actions)
	return actions
}

// walkWorkers bounds the worker pool that reads directories in parallel. It is
// kept deliberately small: the action walk runs concurrently with the CPU-bound
// shellcheck precompute (see cmd/root), and a large pool would steal cores from
// shellcheck — the dominant cost — for directory reads that are largely kernel
// work. A couple of workers overlap the read latency while leaving the cores
// free, which minimizes total wall time even though the walk itself finishes a
// little later.
var walkWorkers = max(runtime.NumCPU()/4, 2)

// walkActions recursively finds action.yml/action.yaml files under baseDir,
// excluding .git and node_modules, using a fixed pool of workers that share a
// LIFO directory stack. Paths already present in workflowSet (absolute) or under
// .github/workflows/ are skipped.
func walkActions(baseDir string, workflowSet map[string]struct{}) []string {
	var (
		mu      sync.Mutex
		cond    = sync.NewCond(&mu)
		stack   = []string{baseDir}
		active  int // workers currently reading a directory
		actions []string
		wg      sync.WaitGroup
	)

	worker := func() {
		defer wg.Done()
		for {
			mu.Lock()
			for len(stack) == 0 && active > 0 {
				cond.Wait()
			}
			if len(stack) == 0 {
				// No work left and no worker can produce more: terminate, waking
				// any peers still parked so they observe the same condition.
				mu.Unlock()
				cond.Broadcast()
				return
			}
			dir := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			active++
			mu.Unlock()

			// Use *File.ReadDir rather than os.ReadDir to skip the per-directory
			// name sort: the final action list is sorted once at the end, so entry
			// order here is irrelevant, and the walk's directory reads run on the
			// critical path alongside shellcheck.
			f, err := os.Open(dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", dir, err)
				mu.Lock()
				active--
				mu.Unlock()
				cond.Broadcast()
				continue
			}
			entries, err := f.ReadDir(-1)
			_ = f.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", dir, err)
				mu.Lock()
				active--
				mu.Unlock()
				cond.Broadcast()
				continue
			}

			var subdirs []string
			var matched []string
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() {
					if name == ".git" || name == "node_modules" {
						continue
					}
					subdirs = append(subdirs, filepath.Join(dir, name))
					continue
				}

				if name != "action.yml" && name != "action.yaml" {
					continue
				}
				path := filepath.Join(dir, name)

				// Normalize to check if already in workflow set.
				cleanPath := path
				if !filepath.IsAbs(cleanPath) {
					abs, absErr := filepath.Abs(cleanPath)
					if absErr != nil {
						fmt.Fprintf(os.Stderr, "warning: failed to resolve absolute path for %s: %v\n", cleanPath, absErr)
						continue
					}
					cleanPath = abs
				}
				if _, dup := workflowSet[cleanPath]; dup {
					continue
				}
				// Skip paths inside .github/workflows/ (belt-and-suspenders).
				if strings.Contains(filepath.ToSlash(path), ".github/workflows/") {
					continue
				}
				matched = append(matched, path)
			}

			mu.Lock()
			stack = append(stack, subdirs...)
			actions = append(actions, matched...)
			active--
			mu.Unlock()
			cond.Broadcast()
		}
	}

	wg.Add(walkWorkers)
	for i := 0; i < walkWorkers; i++ {
		go worker()
	}
	wg.Wait()
	return actions
}
