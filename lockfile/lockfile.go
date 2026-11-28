// Package lockfile reads GitHub Actions workflow dependency lockfiles
// (.github/workflows/actions.lock) and answers what one of them locks for a
// workflow.
//
// GitHub runs a workflow the lockfile lists with every action it uses resolved
// to the commit the lockfile records, and refuses to start it when a step uses
// an action the lockfile does not lock for it. A workflow the lockfile does not
// list runs as it always has.
package lockfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	ghlock "github.com/github/actions-lockfile/go/pkg/lockfile"
)

// Name is the file name of a workflow dependency lockfile.
const Name = "actions.lock"

// sha1Prefix marks a commit recorded as a SHA-1. Commits recorded with another
// algorithm cannot be fetched by the GitHub API's ref parameter, so a lookup
// treats them as not locked.
const sha1Prefix = "sha1-"

// Workflow is what a lockfile records for one workflow file. The zero value
// stands for a workflow no lockfile lists, which GitHub runs unlocked.
type Workflow struct {
	file *ghlock.File
	// pins holds the keys the lockfile lists for the workflow. It is non-nil
	// exactly when the workflow is listed, an empty or null list included.
	pins map[string]struct{}
	// root is the absolute path of the repository the workflow belongs to.
	root string
}

// Locked reports whether a lockfile lists the workflow.
func (w Workflow) Locked() bool { return w.pins != nil }

// Root returns the absolute path of the repository root the workflow belongs
// to: the directory holding its .github directory. It is set by Load and empty
// for a Workflow taken from a File.
func (w Workflow) Root() string { return w.root }

// Dependency is an action a lockfile locks.
type Dependency struct {
	// Commit is the full SHA-1 commit the action is locked to.
	Commit string
	// uses holds the keys of the actions this one uses, as the lockfile
	// records them.
	uses []string
}

// Lookup returns what the workflow locks a step's uses value to: the entry
// the workflow lists for it, with its commit. Sub-path actions share their
// repository's entry, as GitHub resolves them.
func (w Workflow) Lookup(uses string) (Dependency, bool) {
	return lookup(w.entry(uses, w.listed))
}

// LookupFrom returns what the workflow locks a uses value inside the action
// parent to. GitHub resolves such a value from the parent's own entry or from
// the workflow's list, and fails the job when neither has it.
func (w Workflow) LookupFrom(parent Dependency, uses string) (Dependency, bool) {
	return lookup(w.entry(uses, w.listedFrom(parent)))
}

// Listed reports whether the lockfile records a step's uses value for the
// workflow: whether the workflow's list has its key and the lockfile has an
// entry under that key. GitHub refuses to start the workflow otherwise. Unlike
// Lookup, it holds whatever algorithm the entry's commit is recorded with.
func (w Workflow) Listed(uses string) bool {
	_, ok := w.entry(uses, w.listed)
	return ok
}

// ListedFrom reports whether the lockfile records a uses value inside the
// action parent, from the parent's own entry or from the workflow's list.
// GitHub fails the job otherwise.
func (w Workflow) ListedFrom(parent Dependency, uses string) bool {
	_, ok := w.entry(uses, w.listedFrom(parent))
	return ok
}

func (w Workflow) listed(key string) bool {
	_, ok := w.pins[key]
	return ok
}

func (w Workflow) listedFrom(parent Dependency) func(key string) bool {
	return func(key string) bool {
		return slices.Contains(parent.uses, key) || w.listed(key)
	}
}

// entry returns the lockfile's entry for a uses value, when reachable reports
// its key as one the workflow can resolve it by.
func (w Workflow) entry(uses string, reachable func(key string) bool) (ghlock.Action, bool) {
	if !w.Locked() {
		return ghlock.Action{}, false
	}
	ref := ghlock.ParseActionRef(uses)
	if ref == nil {
		return ghlock.Action{}, false
	}
	key := ghlock.IndexKey(ref.Owner, ref.Repo, ref.Ref)
	if !reachable(key) {
		return ghlock.Action{}, false
	}
	action, ok := w.file.Dependencies[key]
	return action, ok
}

// lookup returns the dependency an entry records, when its commit is a SHA-1.
func lookup(action ghlock.Action, ok bool) (Dependency, bool) {
	if !ok {
		return Dependency{}, false
	}
	commit, ok := strings.CutPrefix(action.Commit, sha1Prefix)
	if !ok {
		return Dependency{}, false
	}
	return Dependency{Commit: commit, uses: action.Uses}, true
}

// File is a parsed lockfile.
type File struct {
	file ghlock.File
}

// Parse parses the contents of a lockfile.
func Parse(contents []byte) (*File, error) {
	f, err := ghlock.Parse(contents)
	if err != nil {
		return nil, err
	}
	return &File{file: f}, nil
}

// Workflow returns what the lockfile records for the workflow it lists under
// key, a path relative to the repository root such as
// ".github/workflows/ci.yml".
func (f *File) Workflow(key string) Workflow {
	keys, ok := f.file.LookupWorkflow(key)
	if !ok {
		return Workflow{}
	}
	pins := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		pins[k] = struct{}{}
	}
	return Workflow{file: &f.file, pins: pins}
}

// ReadError reports a lockfile that exists but could not be read. Ghasec then
// treats the workflows beside it as unlocked.
type ReadError struct {
	// Path is the lockfile's path, in the form the workflow path was given.
	Path string
	Err  error
}

func (e *ReadError) Error() string {
	reason := e.Err.Error()
	if errors.Is(e.Err, ghlock.ErrFutureVersion) {
		reason = "its version is newer than this ghasec supports; upgrade ghasec"
	}
	return fmt.Sprintf("could not read %s: %s", e.Path, reason)
}

func (e *ReadError) Unwrap() error { return e.Err }

// Load reads the lockfile of each workflow file and returns what it records
// for the workflow, keyed by the path as given. A workflow without a lockfile
// is absent from the result, as is one whose lockfile could not be read; each
// such lockfile is reported once, as a *ReadError.
func Load(workflows []string) (map[string]Workflow, []error) {
	type result struct {
		file *File
		err  error
	}
	read := map[string]result{}
	locks := map[string]Workflow{}
	var errs []error
	for _, path := range workflows {
		lockPath, key, root, ok := locate(path)
		if !ok {
			continue
		}
		abs, err := filepath.Abs(lockPath)
		if err != nil {
			continue
		}
		r, seen := read[abs]
		if !seen {
			f, err := readFile(lockPath)
			if err != nil {
				err = &ReadError{Path: lockPath, Err: err}
				errs = append(errs, err)
			}
			r = result{file: f, err: err}
			read[abs] = r
		}
		if r.file == nil {
			continue
		}
		if w := r.file.Workflow(key); w.Locked() {
			w.root = root
			locks[path] = w
		}
	}
	slices.SortFunc(errs, func(a, b error) int {
		return strings.Compare(a.(*ReadError).Path, b.(*ReadError).Path)
	})
	return locks, errs
}

// locate returns where the lockfile for a workflow file lies, the key it
// would list the workflow under, and the absolute path of the repository root.
// GitHub reads a lockfile only for workflows directly under .github/workflows,
// so other files have none.
func locate(path string) (lockPath, key, root string, ok bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", "", false
	}
	dir := filepath.Dir(abs)
	if filepath.Base(dir) != "workflows" || filepath.Base(filepath.Dir(dir)) != ".github" {
		return "", "", "", false
	}
	return filepath.Join(filepath.Dir(path), Name), ".github/workflows/" + filepath.Base(abs), filepath.Dir(filepath.Dir(dir)), true
}

// readFile reads and parses the lockfile at path. A missing file is no
// lockfile, so it returns nil with no error.
func readFile(path string) (*File, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, unwrapPathError(err)
	}
	defer func() { _ = f.Close() }()

	// Reading one byte past the limit lets the parser report the file as too
	// large without reading all of it.
	contents, err := io.ReadAll(io.LimitReader(f, ghlock.MaxParseSize+1))
	if err != nil {
		return nil, unwrapPathError(err)
	}
	return Parse(contents)
}

// unwrapPathError drops the operation and path from a file system error, since
// ReadError already names the file.
func unwrapPathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
