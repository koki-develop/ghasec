package unlockedaction

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/lockfile"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
)

const id = "unlocked-action"

// Rule checks that a workflow a dependency lockfile lists uses only actions
// the lockfile records for it.
type Rule struct{}

func (r *Rule) ID() string     { return id }
func (r *Rule) Required() bool { return false }
func (r *Rule) Online() bool   { return false }

func (r *Rule) Why() string {
	return "GitHub runs a workflow listed in a dependency lockfile only with the actions the lockfile records for it. An unrecorded action keeps the workflow from starting or fails the job, and when the workflow's list is empty, actions inside composite actions of the same repository run unlocked"
}

func (r *Rule) Fix() string {
	return "Run `gh actions-lock` to record the action in the lockfile"
}

// CheckWorkflow reports the remote actions a locked workflow's steps use that
// the lockfile does not record for it, and those used inside the composite
// actions of the same repository the steps run, which it reads from the
// repository. An action file cannot be locked, so the rule does not check
// action files.
func (r *Rule) CheckWorkflow(mapping workflow.WorkflowMapping) []*diagnostic.Error {
	lock := mapping.Lock
	if !lock.Locked() {
		return nil
	}
	return rules.CollectStepErrors(mapping.EachStep, func(step workflow.StepMapping) []*diagnostic.Error {
		return checkStep(step, lock)
	})
}

func checkStep(step workflow.StepMapping, lock lockfile.Workflow) []*diagnostic.Error {
	ref, ok := step.Uses()
	if !ok {
		return nil
	}
	if ref.IsRemote() {
		if lock.Listed(ref.String()) {
			return nil
		}
		return []*diagnostic.Error{{
			Token:   ref.Token(),
			Message: fmt.Sprintf("%q must be locked for this workflow in actions.lock", ref.String()),
		}}
	}

	dir, ok := actionDir(lock.Root(), ref)
	if !ok {
		return nil
	}
	w := &compositeWalk{root: lock.Root(), lock: lock, ref: ref, visited: map[string]bool{}, reported: map[string]bool{}}
	w.walk(dir, nil)
	return w.errs
}

// compositeWalk follows the composite actions of the repository a step runs,
// reporting each remote action used inside them that the lockfile does not
// record for the workflow. GitHub resolves those from the workflow's list
// alone, since the repository's own actions have no entry of their own.
type compositeWalk struct {
	root string
	lock lockfile.Workflow
	// ref is the step's uses value, which every report points at.
	ref      workflow.ActionRef
	visited  map[string]bool
	reported map[string]bool
	errs     []*diagnostic.Error
}

// walk inspects the action in dir. path is nil for the step's action and
// names the actions between it and the one in dir otherwise, so the step's
// action is left out of via.
func (w *compositeWalk) walk(dir string, path []string) {
	if w.visited[dir] {
		return
	}
	w.visited[dir] = true

	m, ok := readAction(dir)
	if !ok {
		return
	}
	if path == nil {
		path = []string{}
	}
	m.EachStep(func(step workflow.StepMapping) {
		inner, ok := step.Uses()
		if !ok {
			return
		}
		if inner.IsRemote() {
			if w.reported[inner.String()] || w.lock.Listed(inner.String()) {
				return
			}
			w.reported[inner.String()] = true
			w.errs = append(w.errs, &diagnostic.Error{
				Token:   w.ref.Token(),
				Message: rules.TransitiveMessage(w.ref, "unlocked action", inner.String(), path),
			})
			return
		}
		if d, ok := actionDir(w.root, inner); ok {
			w.walk(d, append(path[:len(path):len(path)], inner.String()))
		}
	})
}

// actionDir returns the directory of the repository an action of the same
// repository lies in: a self-repository reference ("$/...") resolves against
// the repository, and GitHub reads a workspace-relative one ("./...") from
// the workspace, where the repository is usually checked out. It reports false
// for other references, for a "$/...@ref", which GitHub rejects, and for a
// path leading out of the repository.
func actionDir(root string, ref workflow.ActionRef) (string, bool) {
	var rel string
	switch {
	case ref.IsSelfRepository():
		if strings.Contains(ref.String(), "@") {
			return "", false
		}
		rel = ref.SelfRepositoryPath()
	case ref.IsLocal():
		rel = strings.TrimPrefix(ref.String(), "./")
	default:
		return "", false
	}
	dir := filepath.Join(root, filepath.FromSlash(rel))
	if r, err := filepath.Rel(root, dir); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	return dir, true
}

// readAction reads and parses the action file in dir: action.yml, or
// action.yaml when there is no action.yml, as GitHub looks them up. An action
// that cannot be read or parsed is skipped, as GitHub would fail it.
func readAction(dir string) (workflow.ActionMapping, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "action.yml"))
	if errors.Is(err, fs.ErrNotExist) {
		data, err = os.ReadFile(filepath.Join(dir, "action.yaml"))
	}
	if err != nil {
		return workflow.ActionMapping{}, false
	}
	f, err := yamlparser.ParseBytes(data, 0)
	if err != nil || len(f.Docs) == 0 {
		return workflow.ActionMapping{}, false
	}
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return workflow.ActionMapping{}, false
	}
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}, true
}
