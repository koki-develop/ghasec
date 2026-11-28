package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koki-develop/ghasec/discover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	checkoutSHA = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	cacheSHA    = "0057852bfaa89a56745cba8c7296529d2fc39830"
	sharedSHA   = "1111111111111111111111111111111111111111"
	innerSHA    = "2222222222222222222222222222222222222222"
	upperSHA    = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
)

// sampleLock locks ci.yml and other.yml. Its entries cover the shapes a
// lookup has to tell apart: a tag, a sub-path action's repository, a SHA as
// the workflow wrote it, an entry another workflow lists, an entry listed with
// no record, a record reached only through a parent's uses, and a record
// locked to a SHA-256 commit.
var sampleLock = `version: v0.0.3
workflows:
  .github/workflows/ci.yml:
    - actions/checkout@v6.0.2
    - actions/cache@v4
    - octo/upper@` + upperSHA + `
    - octo/parent@v1
    - octo/listed-inner@v1
    - octo/unrecorded@v1
    - octo/sha256@v1
  .github/workflows/other.yml:
    - octo/elsewhere@v1
dependencies:
  actions/checkout@v6.0.2:
    ref: v6.0.2
    commit: sha1-` + checkoutSHA + `
    owner_id: 44036562
    repo_id: 197814629
  actions/cache@v4:
    ref: v4
    commit: sha1-` + cacheSHA + `
    owner_id: 44036562
    repo_id: 105467887
  octo/upper@` + upperSHA + `:
    ref: main
    commit: sha1-` + strings.ToLower(upperSHA) + `
    owner_id: 1
    repo_id: 2
  octo/parent@v1:
    ref: v1
    commit: sha1-` + sharedSHA + `
    owner_id: 1
    repo_id: 3
    uses:
      - octo/child@v2
  octo/child@v2:
    ref: v2
    commit: sha1-` + innerSHA + `
    owner_id: 1
    repo_id: 4
  octo/listed-inner@v1:
    ref: v1
    commit: sha1-` + innerSHA + `
    owner_id: 1
    repo_id: 5
  octo/unlisted-inner@v1:
    ref: v1
    commit: sha1-` + innerSHA + `
    owner_id: 1
    repo_id: 6
  octo/sha256@v1:
    ref: v1
    commit: sha256-` + "abababababababababababababababababababababababababababababababab" + `
    owner_id: 1
    repo_id: 7
  octo/elsewhere@v1:
    ref: v1
    commit: sha1-` + sharedSHA + `
    owner_id: 1
    repo_id: 8
`

// newRepo creates a repository root holding a .github/workflows directory with
// the given files, and returns the root.
func newRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	return root
}

const workflowContent = "on: push\njobs: {}\n"

// L1
func TestLoad_findsTheLockfileBesideTheWorkflow(t *testing.T) {
	root := newRepo(t, map[string]string{
		".github/workflows/ci.yml":       workflowContent,
		".github/workflows/actions.lock": sampleLock,
	})
	path := filepath.Join(root, ".github/workflows/ci.yml")

	locks, errs := Load([]string{path})
	require.Empty(t, errs)
	w := locks[path]
	assert.True(t, w.Locked())
	dep, ok := w.Lookup("actions/checkout@v6.0.2")
	require.True(t, ok)
	assert.Equal(t, checkoutSHA, dep.Commit)
}

// L2
func TestLoad_withoutALockfileNothingIsLockedAndNothingIsReported(t *testing.T) {
	root := newRepo(t, map[string]string{".github/workflows/ci.yml": workflowContent})
	path := filepath.Join(root, ".github/workflows/ci.yml")

	locks, errs := Load([]string{path})
	assert.Empty(t, errs)
	assert.False(t, locks[path].Locked())
}

// L3
func TestLoad_aWorkflowTheLockfileDoesNotListIsNotLocked(t *testing.T) {
	root := newRepo(t, map[string]string{
		".github/workflows/unlisted.yml": workflowContent,
		".github/workflows/actions.lock": sampleLock,
	})
	path := filepath.Join(root, ".github/workflows/unlisted.yml")

	locks, errs := Load([]string{path})
	require.Empty(t, errs)
	assert.False(t, locks[path].Locked())
}

// L4
func TestLoad_aWorkflowOutsideGithubWorkflowsIsNotLocked(t *testing.T) {
	lock := strings.Replace(sampleLock, "  .github/workflows/other.yml:",
		"  .github/workflows/sub/ci.yml:\n    - actions/checkout@v6.0.2\n  .github/workflows/other.yml:", 1)
	tests := []struct {
		name  string
		files map[string]string
		path  string
	}{
		{
			name: "repository root",
			files: map[string]string{
				"ci.yml":       workflowContent,
				"actions.lock": sampleLock,
			},
			path: "ci.yml",
		},
		{
			name: "subdirectory of .github/workflows",
			files: map[string]string{
				".github/workflows/sub/ci.yml":       workflowContent,
				".github/workflows/sub/actions.lock": lock,
				".github/workflows/actions.lock":     lock,
			},
			path: ".github/workflows/sub/ci.yml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newRepo(t, tt.files)
			path := filepath.Join(root, filepath.FromSlash(tt.path))

			locks, errs := Load([]string{path})
			assert.Empty(t, errs)
			assert.False(t, locks[path].Locked())
		})
	}
}

// L5
func TestLoad_pathForms(t *testing.T) {
	lock := strings.Replace(sampleLock, "  .github/workflows/other.yml:",
		"  .github/workflows/release.yaml:\n    - actions/checkout@v6.0.2\n  .github/workflows/Upper.yml:\n    - actions/checkout@v6.0.2\n  .github/workflows/other.yml:", 1)

	t.Run("relative path from inside the directory", func(t *testing.T) {
		root := newRepo(t, map[string]string{
			".github/workflows/ci.yml":       workflowContent,
			".github/workflows/actions.lock": lock,
		})
		t.Chdir(filepath.Join(root, ".github/workflows"))

		locks, errs := Load([]string{"ci.yml"})
		require.Empty(t, errs)
		assert.True(t, locks["ci.yml"].Locked())
	})

	t.Run(".yaml extension", func(t *testing.T) {
		root := newRepo(t, map[string]string{
			".github/workflows/release.yaml": workflowContent,
			".github/workflows/actions.lock": lock,
		})
		path := filepath.Join(root, ".github/workflows/release.yaml")

		locks, errs := Load([]string{path})
		require.Empty(t, errs)
		assert.True(t, locks[path].Locked())
	})

	t.Run("paths auto-discovery gives for a relative workdir", func(t *testing.T) {
		root := newRepo(t, map[string]string{
			"repo/.github/workflows/ci.yml":       workflowContent,
			"repo/.github/workflows/actions.lock": lock,
		})
		t.Chdir(root)
		paths, _, err := discover.GlobWorkflows("repo")
		require.NoError(t, err)
		require.Len(t, paths, 1)

		locks, errs := Load(paths)
		require.Empty(t, errs)
		assert.True(t, locks[paths[0]].Locked())
	})

	t.Run("file name differing in case from the key", func(t *testing.T) {
		root := newRepo(t, map[string]string{
			".github/workflows/upper.yml":    workflowContent,
			".github/workflows/actions.lock": lock,
		})
		path := filepath.Join(root, ".github/workflows/upper.yml")

		locks, errs := Load([]string{path})
		require.Empty(t, errs)
		assert.False(t, locks[path].Locked())
	})
}

// L6
func TestLoad_anEmptyOrNullListStillLocksTheWorkflow(t *testing.T) {
	lock := `version: v0.0.3
workflows:
  .github/workflows/empty.yml: []
  .github/workflows/null.yml: ~
dependencies: {}
`
	root := newRepo(t, map[string]string{
		".github/workflows/empty.yml":    workflowContent,
		".github/workflows/null.yml":     workflowContent,
		".github/workflows/actions.lock": lock,
	})
	empty := filepath.Join(root, ".github/workflows/empty.yml")
	null := filepath.Join(root, ".github/workflows/null.yml")

	locks, errs := Load([]string{empty, null})
	require.Empty(t, errs)
	assert.True(t, locks[empty].Locked())
	assert.True(t, locks[null].Locked())
}

func ciWorkflow(t *testing.T) Workflow {
	t.Helper()
	root := newRepo(t, map[string]string{
		".github/workflows/ci.yml":       workflowContent,
		".github/workflows/actions.lock": sampleLock,
	})
	path := filepath.Join(root, ".github/workflows/ci.yml")
	locks, errs := Load([]string{path})
	require.Empty(t, errs)
	return locks[path]
}

// L7
func TestWorkflow_Lookup_findsTheLockedCommit(t *testing.T) {
	w := ciWorkflow(t)
	tests := []struct {
		uses   string
		commit string
	}{
		{uses: "Actions/Checkout@v6.0.2", commit: checkoutSHA},
		{uses: "actions/cache/save@v4", commit: cacheSHA},
		{uses: "actions/cache/restore@v4", commit: cacheSHA},
		{uses: "octo/upper@" + upperSHA, commit: strings.ToLower(upperSHA)},
	}
	for _, tt := range tests {
		t.Run(tt.uses, func(t *testing.T) {
			dep, ok := w.Lookup(tt.uses)
			require.True(t, ok)
			assert.Equal(t, tt.commit, dep.Commit)
		})
	}
}

// L8
func TestWorkflow_Lookup_findsNothingTheWorkflowDoesNotLock(t *testing.T) {
	w := ciWorkflow(t)
	tests := []struct {
		name string
		uses string
	}{
		{name: "another ref of a locked action", uses: "actions/checkout@v6"},
		{name: "listed only for another workflow", uses: "octo/elsewhere@v1"},
		{name: "listed with no record", uses: "octo/unrecorded@v1"},
		{name: "SHA in another case than the key", uses: "octo/upper@" + strings.ToLower(upperSHA)},
		{name: "recorded but listed nowhere", uses: "octo/unlisted-inner@v1"},
		{name: "locked to a SHA-256 commit", uses: "octo/sha256@v1"},
		{name: "docker image", uses: "docker://alpine:3.22"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := w.Lookup(tt.uses)
			assert.False(t, ok)
		})
	}
}

func TestWorkflow_LookupFrom(t *testing.T) {
	w := ciWorkflow(t)
	parent, ok := w.Lookup("octo/parent@v1")
	require.True(t, ok)

	tests := []struct {
		name   string
		uses   string
		commit string
		ok     bool
	}{
		{name: "in the parent's uses", uses: "octo/child@v2", commit: innerSHA, ok: true},
		{name: "in the workflow's list", uses: "octo/listed-inner@v1", commit: innerSHA, ok: true},
		{name: "in neither", uses: "octo/unlisted-inner@v1"},
		{name: "locked to a SHA-256 commit", uses: "octo/sha256@v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep, ok := w.LookupFrom(parent, tt.uses)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.commit, dep.Commit)
		})
	}
}

// L9
func TestLoad_anUnreadableLockfileIsReportedAndLocksNothing(t *testing.T) {
	tests := []struct {
		name    string
		lock    string
		lockDir bool
		message string
	}{
		{name: "broken YAML", lock: "version: [", message: "could not read .github/workflows/actions.lock: line 1: did not find expected node content"},
		{name: "future version", lock: "version: v9.9.9\nworkflows: {}\ndependencies: {}\n", message: "could not read .github/workflows/actions.lock: its version is newer than this ghasec supports; upgrade ghasec"},
		{name: "larger than 1 MiB", lock: "version: v0.0.3\n" + strings.Repeat("#", 1<<20), message: "could not read .github/workflows/actions.lock: lockfile too large"},
		{name: "directory", lockDir: true, message: "could not read .github/workflows/actions.lock: is a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{".github/workflows/ci.yml": workflowContent}
			if !tt.lockDir {
				files[".github/workflows/actions.lock"] = tt.lock
			}
			root := newRepo(t, files)
			if tt.lockDir {
				require.NoError(t, os.Mkdir(filepath.Join(root, ".github/workflows/actions.lock"), 0o755))
			}
			t.Chdir(root)
			path := ".github/workflows/ci.yml"

			locks, errs := Load([]string{path})
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Error(), tt.message)
			assert.False(t, locks[path].Locked())
		})
	}
}

func TestLoad_readsEachLockfileOnce(t *testing.T) {
	root := newRepo(t, map[string]string{
		".github/workflows/ci.yml":       workflowContent,
		".github/workflows/other.yml":    workflowContent,
		".github/workflows/actions.lock": "version: [",
	})
	paths := []string{
		filepath.Join(root, ".github/workflows/ci.yml"),
		filepath.Join(root, ".github/workflows/other.yml"),
	}

	_, errs := Load(paths)
	assert.Len(t, errs, 1)
}

// L10
func TestLoad_readsOlderFormats(t *testing.T) {
	tests := []struct {
		name string
		lock string
	}{
		{
			name: "v0.0.2",
			lock: `version: v0.0.2
workflows:
  .github/workflows/ci.yml:
    - actions/checkout@v6.0.2
dependencies:
  actions/checkout@v6.0.2:
    ref: v6.0.2
    commit: sha1-` + checkoutSHA + `
    owner_id: 44036562
    repo_id: 197814629
`,
		},
		{
			name: "v0.0.1",
			lock: `version: v0.0.1
workflows:
  .github/workflows/ci.yml:
    - actions/checkout@v6.0.2:sha1-` + checkoutSHA + `
dependencies:
  actions/checkout@v6.0.2:sha1-` + checkoutSHA + `:
    tag: v6.0.2
    commit: sha1-` + checkoutSHA + `
    owner_id: 44036562
    repo_id: 197814629
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newRepo(t, map[string]string{
				".github/workflows/ci.yml":       workflowContent,
				".github/workflows/actions.lock": tt.lock,
			})
			path := filepath.Join(root, ".github/workflows/ci.yml")

			locks, errs := Load([]string{path})
			require.Empty(t, errs)
			dep, ok := locks[path].Lookup("actions/checkout@v6.0.2")
			require.True(t, ok)
			assert.Equal(t, checkoutSHA, dep.Commit)
		})
	}
}

// L11
func TestWorkflow_zeroValueIsNotLocked(t *testing.T) {
	var w Workflow
	assert.False(t, w.Locked())
	_, ok := w.Lookup("actions/checkout@v6.0.2")
	assert.False(t, ok)
	_, ok = w.LookupFrom(Dependency{}, "actions/checkout@v6.0.2")
	assert.False(t, ok)
}
