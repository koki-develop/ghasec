package unlockedaction

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/lockfile"
	"github.com/koki-develop/ghasec/rules"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	checkoutSHA = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
	upperSHA    = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
)

// lock lists ci.yml with a tag, a repository whose sub-path actions share its
// entry, a SHA written in upper case and one in lower case, an entry listed with no record, and one
// locked to a SHA-256 commit. other.yml is not listed.
const lock = `version: v0.0.3
workflows:
  .github/workflows/ci.yml:
    - actions/checkout@v6.0.2
    - actions/cache@v4
    - octo/upper@` + upperSHA + `
    - octo/lower@0123456789abcdef0123456789abcdef01234567
    - octo/unrecorded@v1
    - octo/sha256@v1
dependencies:
  actions/checkout@v6.0.2: {ref: v6.0.2, commit: sha1-` + checkoutSHA + `, owner_id: 44036562, repo_id: 197814629}
  actions/cache@v4: {ref: v4, commit: sha1-0057852bfaa89a56745cba8c7296529d2fc39830, owner_id: 44036562, repo_id: 105467887}
  octo/upper@` + upperSHA + `: {ref: main, commit: sha1-abcdef0123456789abcdef0123456789abcdef01, owner_id: 1, repo_id: 2}
  octo/lower@0123456789abcdef0123456789abcdef01234567: {ref: main, commit: sha1-0123456789abcdef0123456789abcdef01234567, owner_id: 1, repo_id: 4}
  octo/sha256@v1: {ref: v1, commit: sha256-abababababababababababababababababababababababababababababababab, owner_id: 1, repo_id: 3}
`

// emptyLock lists ci.yml with an empty list and other.yml with a null one.
const emptyLock = `version: v0.0.3
workflows:
  .github/workflows/ci.yml: []
  .github/workflows/other.yml: ~
dependencies: {}
`

// workflowWith returns a workflow whose job runs the given steps, one uses
// value each.
func workflowWith(uses ...string) string {
	s := "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, u := range uses {
		s += "      - uses: " + u + "\n"
	}
	return s
}

// compositeWith returns a composite action running the given uses values.
func compositeWith(uses ...string) string {
	s := "name: X\ndescription: X\nruns:\n  using: composite\n  steps:\n"
	for _, u := range uses {
		s += "    - uses: " + u + "\n"
	}
	return s
}

// check writes files under a repository root inside a temporary directory,
// lints the workflow at name, and returns the diagnostics. The lockfile
// .github/workflows/actions.lock is one of the files when the workflow is to
// be locked.
func check(t *testing.T, name string, files map[string]string) []*diagnostic.Error {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	for p, content := range files {
		dst := filepath.Join(root, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
		require.NoError(t, os.WriteFile(dst, []byte(content), 0o644))
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	locks, errs := lockfile.Load([]string{path})
	require.Empty(t, errs)

	f, err := yamlparser.ParseFile(path, 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return (&Rule{}).CheckWorkflow(workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}, Lock: locks[path]})
}

// report is a diagnostic as the tests compare it: where it points and what it
// says.
type report struct {
	Line    int
	Value   string
	Message string
}

func reports(errs []*diagnostic.Error) []report {
	var out []report
	for _, e := range errs {
		out = append(out, report{Line: e.Token.Position.Line, Value: e.Token.Value, Message: e.Message})
	}
	return out
}

const ci = ".github/workflows/ci.yml"

func TestRule_Metadata(t *testing.T) {
	r := &Rule{}
	assert.Equal(t, "unlocked-action", r.ID())
	assert.False(t, r.Required())
	assert.False(t, r.Online())
	assert.NotEmpty(t, r.Why())
	assert.NotEmpty(t, r.Fix())
}

// U1
func TestRule_listedActionIsNotReported(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                               workflowWith("actions/checkout@v6.0.2"),
		".github/workflows/actions.lock": lock,
	})
	assert.Empty(t, errs)
}

// U2, U3
func TestRule_unlistedActionIsReported(t *testing.T) {
	tests := []struct {
		name string
		uses string
	}{
		{name: "tag", uses: "actions/setup-go@v6.5.0"},
		{name: "full SHA", uses: "actions/setup-go@" + checkoutSHA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := check(t, ci, map[string]string{
				ci:                               workflowWith("actions/checkout@v6.0.2", tt.uses),
				".github/workflows/actions.lock": lock,
			})
			assert.Equal(t, []report{
				{Line: 7, Value: tt.uses, Message: `"` + tt.uses + `" must be locked for this workflow in actions.lock`},
			}, reports(errs))
		})
	}
}

// U4
func TestRule_workflowTheLockfileDoesNotListIsNotChecked(t *testing.T) {
	errs := check(t, ".github/workflows/other.yml", map[string]string{
		".github/workflows/other.yml":      workflowWith("actions/setup-go@v6.5.0", "$/.github/actions/setup"),
		".github/actions/setup/action.yml": compositeWith("actions/setup-node@v6"),
		".github/workflows/actions.lock":   lock,
	})
	assert.Empty(t, errs)
}

// U4: a workflow without a lockfile is not checked either.
func TestRule_workflowWithoutALockfileIsNotChecked(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                                 workflowWith("actions/setup-go@v6.5.0", "$/.github/actions/setup"),
		".github/actions/setup/action.yml": compositeWith("actions/setup-node@v6"),
	})
	assert.Empty(t, errs)
}

// U5
func TestRule_emptyOrNullListReportsEveryAction(t *testing.T) {
	for _, name := range []string{ci, ".github/workflows/other.yml"} {
		t.Run(name, func(t *testing.T) {
			errs := check(t, name, map[string]string{
				name:                               workflowWith("actions/checkout@v6.0.2", "$/.github/actions/setup"),
				".github/actions/setup/action.yml": compositeWith("actions/setup-node@v6"),
				".github/workflows/actions.lock":   emptyLock,
			})
			assert.Equal(t, []report{
				{Line: 6, Value: "actions/checkout@v6.0.2", Message: `"actions/checkout@v6.0.2" must be locked for this workflow in actions.lock`},
				{Line: 7, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6"`},
			}, reports(errs))
		})
	}
}

// U6, U7, U8, U9
func TestRule_keys(t *testing.T) {
	tests := []struct {
		name     string
		uses     string
		reported bool
	}{
		{name: "sub-path of a listed repository", uses: "actions/cache/save@v4"},
		{name: "owner and repository in another case", uses: "Actions/Checkout@v6.0.2"},
		{name: "SHA in the case of the key", uses: "octo/upper@" + upperSHA},
		{name: "locked to a SHA-256 commit", uses: "octo/sha256@v1"},
		{name: "SHA in another case than the key", uses: "octo/upper@abcdef0123456789abcdef0123456789abcdef01", reported: true},
		{name: "SHA in upper case, key in lower case", uses: "octo/lower@0123456789ABCDEF0123456789ABCDEF01234567", reported: true},
		{name: "listed with no record", uses: "octo/unrecorded@v1", reported: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := check(t, ci, map[string]string{
				ci:                               workflowWith(tt.uses),
				".github/workflows/actions.lock": lock,
			})
			if !tt.reported {
				assert.Empty(t, errs)
				return
			}
			assert.Equal(t, []report{
				{Line: 6, Value: tt.uses, Message: `"` + tt.uses + `" must be locked for this workflow in actions.lock`},
			}, reports(errs))
		})
	}
}

// U10
func TestRule_referencesNotLockedAreNotReported(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci: `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/missing
      - uses: docker://alpine:3.22
      - uses: $/.github/actions/plain
  call:
    uses: octo/repo/.github/workflows/build.yml@v1
`,
		".github/actions/plain/action.yml": compositeWith("actions/checkout@v6.0.2"),
		".github/workflows/actions.lock":   lock,
	})
	assert.Empty(t, errs)
}

// U11, U12
func TestRule_selfRepositoryComposite(t *testing.T) {
	tests := []struct {
		name  string
		inner []string
		want  []report
	}{
		{
			name:  "listed inside",
			inner: []string{"actions/checkout@v6.0.2", "actions/cache/save@v4", "docker://alpine:3.22"},
		},
		{
			name:  "unlisted inside",
			inner: []string{"actions/checkout@v6.0.2", "actions/setup-node@v6"},
			want: []report{
				{Line: 6, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6"`},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := check(t, ci, map[string]string{
				ci:                                 workflowWith("$/.github/actions/setup"),
				".github/actions/setup/action.yml": compositeWith(tt.inner...),
				".github/workflows/actions.lock":   lock,
			})
			assert.Equal(t, tt.want, reports(errs))
		})
	}
}

// U13
func TestRule_nestedSelfRepositoryCompositeIsNamedVia(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                                 workflowWith("$/.github/actions/setup"),
		".github/actions/setup/action.yml": compositeWith("$/.github/actions/inner"),
		".github/actions/inner/action.yml": compositeWith("actions/setup-node@v6"),
		".github/workflows/actions.lock":   lock,
	})
	assert.Equal(t, []report{
		{Line: 6, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6" via "$/.github/actions/inner"`},
	}, reports(errs))
}

// U14
func TestRule_eachUnlistedActionIsReportedOncePerStep(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                                 workflowWith("$/.github/actions/setup"),
		".github/actions/setup/action.yml": compositeWith("actions/setup-node@v6", "$/.github/actions/inner", "actions/setup-node@v6", "actions/setup-go@v6"),
		".github/actions/inner/action.yml": compositeWith("actions/setup-node@v6"),
		".github/workflows/actions.lock":   lock,
	})
	assert.Equal(t, []report{
		{Line: 6, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6"`},
		{Line: 6, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-go@v6"`},
	}, reports(errs))
}

// U15
func TestRule_eachStepIsReportedOnItsOwn(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                                 workflowWith("actions/setup-node@v6", "$/.github/actions/setup", "$/.github/actions/setup"),
		".github/actions/setup/action.yml": compositeWith("actions/setup-node@v6"),
		".github/workflows/actions.lock":   lock,
	})
	assert.Equal(t, []report{
		{Line: 6, Value: "actions/setup-node@v6", Message: `"actions/setup-node@v6" must be locked for this workflow in actions.lock`},
		{Line: 7, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6"`},
		{Line: 8, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6"`},
	}, reports(errs))
}

// U16
func TestRule_actionFileThatCannotBeReadIsSkipped(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "missing", files: map[string]string{}},
		{name: "unreadable", files: map[string]string{".github/actions/setup/action.yml/x": "x"}},
		{name: "broken YAML", files: map[string]string{".github/actions/setup/action.yml": "runs: [\n"}},
		{name: "not a mapping", files: map[string]string{".github/actions/setup/action.yml": "- a\n"}},
		{name: "empty", files: map[string]string{".github/actions/setup/action.yml": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				ci:                               workflowWith("$/.github/actions/setup", "actions/setup-go@v6"),
				".github/workflows/actions.lock": lock,
			}
			for k, v := range tt.files {
				files[k] = v
			}
			errs := check(t, ci, files)
			assert.Equal(t, []report{
				{Line: 7, Value: "actions/setup-go@v6", Message: `"actions/setup-go@v6" must be locked for this workflow in actions.lock`},
			}, reports(errs))
		})
	}
}

// U17
func TestRule_actionThatIsNotCompositeIsNotFollowed(t *testing.T) {
	tests := []struct {
		name   string
		action string
	}{
		{name: "node", action: "name: X\ndescription: X\nruns:\n  using: node24\n  main: index.js\n"},
		{name: "docker", action: "name: X\ndescription: X\nruns:\n  using: docker\n  image: Dockerfile\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := check(t, ci, map[string]string{
				ci:                                 workflowWith("$/.github/actions/setup"),
				".github/actions/setup/action.yml": tt.action,
				".github/workflows/actions.lock":   lock,
			})
			assert.Empty(t, errs)
		})
	}
}

// U18
func TestRule_cycleIsFollowedOnce(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                               workflowWith("$/.github/actions/a"),
		".github/actions/a/action.yml":   compositeWith("$/.github/actions/b"),
		".github/actions/b/action.yml":   compositeWith("$/.github/actions/a", "actions/setup-node@v6"),
		".github/workflows/actions.lock": lock,
	})
	assert.Equal(t, []report{
		{Line: 6, Value: "$/.github/actions/a", Message: `"$/.github/actions/a" uses unlocked action "actions/setup-node@v6" via "$/.github/actions/b"`},
	}, reports(errs))
}

// U19
func TestRule_actionFileNames(t *testing.T) {
	t.Run("action.yaml alone", func(t *testing.T) {
		errs := check(t, ci, map[string]string{
			ci:                                  workflowWith("$/.github/actions/setup"),
			".github/actions/setup/action.yaml": compositeWith("actions/setup-node@v6"),
			".github/workflows/actions.lock":    lock,
		})
		assert.Equal(t, []report{
			{Line: 6, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6"`},
		}, reports(errs))
	})

	t.Run("action.yml before action.yaml", func(t *testing.T) {
		errs := check(t, ci, map[string]string{
			ci:                                  workflowWith("$/.github/actions/setup"),
			".github/actions/setup/action.yml":  compositeWith("actions/setup-node@v6"),
			".github/actions/setup/action.yaml": compositeWith("actions/setup-go@v6"),
			".github/workflows/actions.lock":    lock,
		})
		assert.Equal(t, []report{
			{Line: 6, Value: "$/.github/actions/setup", Message: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6"`},
		}, reports(errs))
	})
}

// U20
func TestRule_repositoryRootAction(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                               workflowWith("$/"),
		"action.yml":                     compositeWith("actions/setup-node@v6"),
		".github/workflows/actions.lock": lock,
	})
	assert.Equal(t, []report{
		{Line: 6, Value: "$/", Message: `"$/" uses unlocked action "actions/setup-node@v6"`},
	}, reports(errs))
}

// U21
func TestRule_pathOutsideTheRepositoryIsNotRead(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                               workflowWith("$/../outside", "./../outside"),
		"../outside/action.yml":          compositeWith("actions/setup-node@v6"),
		".github/workflows/actions.lock": lock,
	})
	assert.Empty(t, errs)
}

// U22
func TestRule_selfRepositoryReferenceWithRefIsNotFollowed(t *testing.T) {
	errs := check(t, ci, map[string]string{
		ci:                                 workflowWith("$/.github/actions/setup@v1"),
		".github/actions/setup/action.yml": compositeWith("actions/setup-node@v6"),
		".github/workflows/actions.lock":   lock,
	})
	assert.Empty(t, errs)
}

// U23
func TestRule_workspaceRelativeComposite(t *testing.T) {
	tests := []struct {
		name  string
		step  string
		files map[string]string
		want  string
	}{
		{
			name:  "./ step",
			step:  "./.github/actions/setup",
			files: map[string]string{".github/actions/setup/action.yml": compositeWith("actions/setup-node@v6")},
			want:  `"./.github/actions/setup" uses unlocked action "actions/setup-node@v6"`,
		},
		{
			name: "./ inside $/",
			step: "$/.github/actions/setup",
			files: map[string]string{
				".github/actions/setup/action.yml": compositeWith("./.github/actions/inner"),
				".github/actions/inner/action.yml": compositeWith("actions/setup-node@v6"),
			},
			want: `"$/.github/actions/setup" uses unlocked action "actions/setup-node@v6" via "./.github/actions/inner"`,
		},
		{
			name: "$/ inside ./",
			step: "./.github/actions/setup",
			files: map[string]string{
				".github/actions/setup/action.yml": compositeWith("$/.github/actions/inner"),
				".github/actions/inner/action.yml": compositeWith("actions/setup-node@v6"),
			},
			want: `"./.github/actions/setup" uses unlocked action "actions/setup-node@v6" via "$/.github/actions/inner"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				ci:                               workflowWith(tt.step),
				".github/workflows/actions.lock": lock,
			}
			for k, v := range tt.files {
				files[k] = v
			}
			errs := check(t, ci, files)
			assert.Equal(t, []report{{Line: 6, Value: tt.step, Message: tt.want}}, reports(errs))
		})
	}
}

// U24
func TestRule_doesNotCheckActionFiles(t *testing.T) {
	_, ok := any(&Rule{}).(rules.ActionRule)
	assert.False(t, ok)
}
