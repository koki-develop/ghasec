package unlockedtransitiveaction

import (
	"context"
	"errors"
	"fmt"
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

type mockFetcher struct {
	files map[string]string // key: "owner/repo@ref" or "owner/repo/subpath@ref"
	err   error
	calls []string // keys fetched, in order
}

func (m *mockFetcher) FetchActionFile(_ context.Context, owner, repo, subPath, ref string) (*ast.File, error) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	if subPath != "" {
		key = fmt.Sprintf("%s/%s/%s@%s", owner, repo, subPath, ref)
	}
	m.calls = append(m.calls, key)
	if m.err != nil {
		return nil, m.err
	}
	src, ok := m.files[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return yamlparser.ParseBytes([]byte(src), 0)
}

const (
	shaB      = "1111111111111111111111111111111111111111"
	shaInPar  = "2222222222222222222222222222222222222222"
	shaInList = "3333333333333333333333333333333333333333"
	shaTwo    = "4444444444444444444444444444444444444444"
	shaMid    = "5555555555555555555555555555555555555555"
	shaCache  = "0057852bfaa89a56745cba8c7296529d2fc39830"
	shaSelf   = "6666666666666666666666666666666666666666"
	shaFail   = "7777777777777777777777777777777777777777"
	shaPinned = "8888888888888888888888888888888888888888"
)

// lock lists ci.yml. Each entry is named for what it stands for: an action
// recorded only in its parent's uses, one in the workflow's list, a parent
// whose child is recorded only in its uses, and actions locked to a SHA-256
// commit.
const lock = `version: v0.0.3
workflows:
  .github/workflows/ci.yml:
    - a/b@v1
    - x/in-list@v1
    - a/two@v1
    - actions/cache@v4
    - a/self@v1
    - a/sha256@v1
    - x/sha256@v1
    - a/fail@v1
dependencies:
  a/b@v1: {ref: v1, commit: sha1-` + shaB + `, owner_id: 1, repo_id: 1, uses: [x/in-parent@v1]}
  x/in-parent@v1: {ref: v1, commit: sha1-` + shaInPar + `, owner_id: 2, repo_id: 2}
  x/in-list@v1: {ref: v1, commit: sha1-` + shaInList + `, owner_id: 2, repo_id: 3}
  a/two@v1: {ref: v1, commit: sha1-` + shaTwo + `, owner_id: 1, repo_id: 4, uses: [b/mid@v1]}
  b/mid@v1: {ref: v1, commit: sha1-` + shaMid + `, owner_id: 3, repo_id: 5}
  actions/cache@v4: {ref: v4, commit: sha1-` + shaCache + `, owner_id: 44036562, repo_id: 105467887}
  a/self@v1: {ref: v1, commit: sha1-` + shaSelf + `, owner_id: 1, repo_id: 6, uses: [x/in-parent@v1]}
  a/sha256@v1: {ref: v1, commit: sha256-abababababababababababababababababababababababababababababababab, owner_id: 1, repo_id: 7}
  x/sha256@v1: {ref: v1, commit: sha256-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd, owner_id: 2, repo_id: 8}
  a/fail@v1: {ref: v1, commit: sha1-` + shaFail + `, owner_id: 1, repo_id: 9}
`

const nodeAction = "name: X\nruns:\n  using: node24\n  main: index.js\n"

// composite returns a composite action running the given uses values.
func composite(uses ...string) string {
	s := "name: X\nruns:\n  using: composite\n  steps:\n"
	for _, u := range uses {
		s += "    - uses: " + u + "\n"
	}
	return s
}

// workflowFor returns a workflow running the given uses values, locked by lock
// under key, or unlocked when key is empty.
func workflowFor(t *testing.T, key string, uses ...string) workflow.WorkflowMapping {
	t.Helper()
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, u := range uses {
		src += "      - uses: " + u + "\n"
	}
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	mapping := workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
	if key != "" {
		lf, err := lockfile.Parse([]byte(lock))
		require.NoError(t, err)
		mapping.Lock = lf.Workflow(key)
	}
	return mapping
}

const ci = ".github/workflows/ci.yml"

// report is a diagnostic as the tests compare it: what it points at and what
// it says.
type report struct {
	Value   string
	Message string
}

func reports(errs []*diagnostic.Error) []report {
	var out []report
	for _, e := range errs {
		out = append(out, report{Value: e.Token.Value, Message: e.Message})
	}
	return out
}

func TestRule_Metadata(t *testing.T) {
	r := &Rule{}
	assert.Equal(t, "unlocked-transitive-action", r.ID())
	assert.False(t, r.Required())
	assert.True(t, r.Online())
	assert.NotEmpty(t, r.Why())
	assert.NotEmpty(t, r.Fix())
}

// T1
func TestRule_innerActionRecordedIsNotReported(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/b@" + shaB:             composite("x/in-parent@v1", "x/in-list@v1"),
		"x/in-parent@" + shaInPar: nodeAction,
		"x/in-list@" + shaInList:  nodeAction,
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/b@v1"))
	assert.Empty(t, errs)
	assert.Equal(t, []string{"a/b@" + shaB, "x/in-parent@" + shaInPar, "x/in-list@" + shaInList}, fetcher.calls)
}

// T2
func TestRule_innerActionRecordedNowhereIsReported(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/b@" + shaB: composite("x/nowhere@v1"),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/b@v1"))
	assert.Equal(t, []report{
		{Value: "a/b@v1", Message: `"a/b@v1" uses unlocked action "x/nowhere@v1"`},
	}, reports(errs))
}

// T3
func TestRule_nestedActionIsNamedVia(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/two@" + shaTwo: composite("b/mid@v1"),
		"b/mid@" + shaMid: composite("c/leaf@v1"),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/two@v1"))
	assert.Equal(t, []report{
		{Value: "a/two@v1", Message: `"a/two@v1" uses unlocked action "c/leaf@v1" via "b/mid@v1"`},
	}, reports(errs))
}

// T4
func TestRule_eachUnrecordedActionIsReported(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/b@" + shaB:             composite("x/one@v1", "x/in-parent@v1", "x/two@v1"),
		"x/in-parent@" + shaInPar: nodeAction,
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/b@v1"))
	assert.Equal(t, []report{
		{Value: "a/b@v1", Message: `"a/b@v1" uses unlocked action "x/one@v1"`},
		{Value: "a/b@v1", Message: `"a/b@v1" uses unlocked action "x/two@v1"`},
	}, reports(errs))
}

// T5
func TestRule_subPathUsesItsRepositorysEntry(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/b@" + shaB:                    composite("actions/cache/save@v4", "actions/setup-go/sub@v6"),
		"actions/cache/save@" + shaCache: nodeAction,
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/b@v1"))
	assert.Equal(t, []report{
		{Value: "a/b@v1", Message: `"a/b@v1" uses unlocked action "actions/setup-go/sub@v6"`},
	}, reports(errs))
}

// T6
func TestRule_selfRepositoryReferenceInsideIsJudgedByTheSameEntry(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/self@" + shaSelf:       composite("$/sub"),
		"a/self/sub@" + shaSelf:   composite("x/in-parent@v1", "x/nowhere@v1"),
		"x/in-parent@" + shaInPar: nodeAction,
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/self@v1"))
	assert.Equal(t, []report{
		{Value: "a/self@v1", Message: `"a/self@v1" uses unlocked action "x/nowhere@v1" via "a/self/sub@v1"`},
	}, reports(errs))
}

// T7
func TestRule_unlistedStepIsLeftToUnlockedAction(t *testing.T) {
	fetcher := &mockFetcher{}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "x/nowhere@v1"))
	assert.Empty(t, errs)
	assert.Empty(t, fetcher.calls)
}

// T8
func TestRule_workflowNotLockedIsNotChecked(t *testing.T) {
	fetcher := &mockFetcher{}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, "", "a/b@v1", "a/pinned@"+shaPinned))
	assert.Empty(t, errs)
	assert.Empty(t, fetcher.calls)
}

// T9
func TestRule_fetchErrorIsLeftToUnpinnedTransitiveAction(t *testing.T) {
	t.Run("step's action", func(t *testing.T) {
		fetcher := &mockFetcher{err: errors.New("boom")}
		errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/fail@v1"))
		assert.Empty(t, errs)
	})

	t.Run("inner action", func(t *testing.T) {
		fetcher := &mockFetcher{files: map[string]string{
			"a/b@" + shaB: composite("x/in-parent@v1", "x/nowhere@v1"),
		}}
		errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/b@v1"))
		assert.Equal(t, []report{
			{Value: "a/b@v1", Message: `"a/b@v1" uses unlocked action "x/nowhere@v1"`},
		}, reports(errs))
	})
}

// T10
func TestRule_commitThatIsNotSHA1(t *testing.T) {
	t.Run("step's action is not fetched", func(t *testing.T) {
		fetcher := &mockFetcher{}
		errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/sha256@v1"))
		assert.Empty(t, errs)
		assert.Empty(t, fetcher.calls)
	})

	t.Run("inner action is recorded but not followed", func(t *testing.T) {
		fetcher := &mockFetcher{files: map[string]string{
			"a/b@" + shaB: composite("x/sha256@v1"),
		}}
		errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/b@v1"))
		assert.Empty(t, errs)
		assert.Equal(t, []string{"a/b@" + shaB}, fetcher.calls)
	})
}

// T11
func TestRule_dockerInsideIsNotReported(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/b@" + shaB: composite("docker://alpine:latest", "./local"),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/b@v1"))
	assert.Empty(t, errs)
}

func TestRule_doesNotCheckActionFiles(t *testing.T) {
	_, ok := any(&Rule{}).(rules.ActionRule)
	assert.False(t, ok)
}

func TestRule_sameUnrecordedActionIsReportedOncePerStep(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]string{
		"a/two@" + shaTwo: composite("x/nowhere@v1", "x/nowhere@v1", "b/mid@v1"),
		"b/mid@" + shaMid: composite("x/nowhere@v1"),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(workflowFor(t, ci, "a/two@v1", "a/two@v1"))
	assert.Equal(t, []report{
		{Value: "a/two@v1", Message: `"a/two@v1" uses unlocked action "x/nowhere@v1"`},
		{Value: "a/two@v1", Message: `"a/two@v1" uses unlocked action "x/nowhere@v1"`},
	}, reports(errs))
}
