package unpinnedtransitiveaction

import (
	"context"
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/diagnostic"
	"github.com/koki-develop/ghasec/lockfile"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockFetcher struct {
	files map[string]*ast.File // key: "owner/repo@ref" or "owner/repo/subpath@ref"
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
	f, ok := m.files[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return f, nil
}

func parseWorkflow(t *testing.T, src string) workflow.WorkflowMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func parseActionFile(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	return f
}

func parseAction(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_SkipsUnpinnedDirect(t *testing.T) {
	r := &Rule{Fetcher: &mockFetcher{}}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_SkipsLocal(t *testing.T) {
	r := &Rule{Fetcher: &mockFetcher{}}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./local\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_SkipsDocker(t *testing.T) {
	r := &Rule{Fetcher: &mockFetcher{}}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://alpine:3.18\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_DetectsUnpinnedDepth1(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses unpinned action")
	assert.Contains(t, errs[0].Message, "other/action-b@v2")
	assert.NotContains(t, errs[0].Message, "via")
}

func TestRule_DetectsUnpinnedDepth2(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"),
		"owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": parseActionFile(t, "name: B\nruns:\n  using: composite\n  steps:\n    - uses: other/action-c@v1\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "other/action-c@v1")
	assert.Contains(t, errs[0].Message, "via")
}

func TestRule_DetectsUnpinnedDepth3(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"),
		"owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": parseActionFile(t, "name: B\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-c@cccccccccccccccccccccccccccccccccccccccc\n"),
		"owner/action-c@cccccccccccccccccccccccccccccccccccccccc": parseActionFile(t, "name: C\nruns:\n  using: composite\n  steps:\n    - uses: other/action-d@main\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "other/action-d@main")
	assert.Contains(t, errs[0].Message, "owner/action-b@")
	assert.Contains(t, errs[0].Message, "owner/action-c@")
}

func TestRule_AllPinnedNoError(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"),
		"owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": parseActionFile(t, "name: B\nruns:\n  using: node20\n  main: index.js\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_CircularReference(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"),
		"owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": parseActionFile(t, "name: B\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_FetchError(t *testing.T) {
	fetcher := &mockFetcher{err: fmt.Errorf("HTTP 500: Internal Server Error")}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, "HTTP 500: Internal Server Error", errs[0].Message, "fetcher errors must be reported as they are")
}

func TestRule_DockerUnpinnedInTransitive(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine:latest\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "unpinned Docker action")
}

func TestRule_DockerPinnedInTransitive(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_CheckAction(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseAction(t, "name: test\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses unpinned action")
}

func TestRule_EmptyRefInTransitive(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/no-ref-action\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "other/no-ref-action")
}

func TestRule_MultipleUnpinnedSteps(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v1\n    - uses: other/action-c@v2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "other/action-b@v1")
	assert.Contains(t, errs[1].Message, "other/action-c@v2")
}

func TestRule_MixedPinnedUnpinnedSteps(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n    - uses: other/action-c@v1\n"),
		"owner/action-b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": parseActionFile(t, "name: B\nruns:\n  using: node20\n  main: index.js\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "other/action-c@v1")
}

func TestRule_StopAtUnpinned(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "other/action-b@v2")
}

func TestRule_EmptyDocumentInFetchedAction(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "---"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NonMappingDocumentInFetchedAction(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "- item1\n- item2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_SubdirectoryAction(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		// key includes subpath: owner/repo/subpath@ref
		"owner/repo/sub/dir@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/repo/sub/dir@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "uses unpinned action")
	assert.Contains(t, errs[0].Message, "other/action-b@v2")
}

func TestRule_SkipsSelfRepository(t *testing.T) {
	r := &Rule{Fetcher: &mockFetcher{err: fmt.Errorf("must not be called")}}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: $/.github/actions/build\n")
	assert.Empty(t, r.CheckWorkflow(m))
}

func TestRule_SelfRepositoryInTransitiveResolvesToParent(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":                 parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: $/internal/helper\n"),
		"owner/action-a/internal/helper@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: Helper\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t,
		`"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" uses unpinned action "other/action-b@v2" via "owner/action-a/internal/helper@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		errs[0].Message,
	)
}

func TestRule_SelfRepositoryInTransitivePinned(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":                 parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: $/internal/helper\n"),
		"owner/action-a/internal/helper@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: Helper\nruns:\n  using: node20\n  main: index.js\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	assert.Empty(t, r.CheckWorkflow(m))
}

func TestRule_SelfRepositoryRootInTransitive(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/repo/sub@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: Sub\nruns:\n  using: composite\n  steps:\n    - uses: $/\n"),
		"owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":     parseActionFile(t, "name: Root\nruns:\n  using: composite\n  steps:\n    - uses: other/action-b@v2\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/repo/sub@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `via "owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
}

func TestRule_SelfRepositoryCycleInTransitive(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/repo/a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: $/b\n"),
		"owner/repo/b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: B\nruns:\n  using: composite\n  steps:\n    - uses: $/a\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/repo/a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	assert.Empty(t, r.CheckWorkflow(m))
}

func TestRule_SelfRepositoryWithRefInTransitiveSkipped(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: $/internal/helper@v1\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/action-a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	assert.Empty(t, r.CheckWorkflow(m))
}

func TestRule_SiblingActionsInSameRepoAreBothChecked(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"owner/repo/a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: A\nruns:\n  using: composite\n  steps:\n    - uses: owner/repo/b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"),
		"owner/repo/b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": parseActionFile(t, "name: B\nruns:\n  using: composite\n  steps:\n    - uses: other/action-c@v1\n"),
	}}
	r := &Rule{Fetcher: fetcher}
	m := parseWorkflow(t, "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/repo/a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t,
		`"owner/repo/a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" uses unpinned action "other/action-c@v1" via "owner/repo/b@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		errs[0].Message,
	)
}

const (
	lockedB      = "1111111111111111111111111111111111111111"
	lockedSHA    = "2222222222222222222222222222222222222222"
	lockedTwo    = "3333333333333333333333333333333333333333"
	lockedMid    = "4444444444444444444444444444444444444444"
	lockedLeaf   = "5555555555555555555555555555555555555555"
	lockedList   = "6666666666666666666666666666666666666666"
	lockedD      = "7777777777777777777777777777777777777777"
	lockedNeith  = "8888888888888888888888888888888888888888"
	lockedF      = "9999999999999999999999999999999999999999"
	lockedCache  = "0057852bfaa89a56745cba8c7296529d2fc39830"
	lockedSelf   = "abababababababababababababababababababab"
	lockedFail   = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	writtenSHA   = "efefefefefefefefefefefefefefefefefefefef"
	dockerInside = "name: X\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine:latest\n"
	nodeAction   = "name: X\nruns:\n  using: node20\n  main: index.js\n"
)

// lockedLock lists ci.yml. Every entry is named for the test that reaches it.
const lockedLock = `version: v0.0.3
workflows:
  .github/workflows/ci.yml:
    - a/b@v1
    - a/sha@` + writtenSHA + `
    - a/two@v1
    - a/list@v1
    - c/d@v2
    - a/neither@v1
    - actions/cache@v4
    - a/self@v1
    - a/sha256@v1
    - a/fail@v1
dependencies:
  a/b@v1: {ref: v1, commit: sha1-` + lockedB + `, owner_id: 1, repo_id: 1}
  a/sha@` + writtenSHA + `: {ref: main, commit: sha1-` + writtenSHA + `, owner_id: 1, repo_id: 2}
  a/two@v1: {ref: v1, commit: sha1-` + lockedTwo + `, owner_id: 1, repo_id: 3, uses: [b/mid@v1]}
  b/mid@v1: {ref: v1, commit: sha1-` + lockedMid + `, owner_id: 2, repo_id: 4, uses: [c/leaf@v1]}
  c/leaf@v1: {ref: v1, commit: sha1-` + lockedLeaf + `, owner_id: 3, repo_id: 5}
  a/list@v1: {ref: v1, commit: sha1-` + lockedList + `, owner_id: 1, repo_id: 6}
  c/d@v2: {ref: v2, commit: sha1-` + lockedD + `, owner_id: 3, repo_id: 7}
  a/neither@v1: {ref: v1, commit: sha1-` + lockedNeith + `, owner_id: 1, repo_id: 8}
  e/f@v1: {ref: v1, commit: sha1-` + lockedF + `, owner_id: 4, repo_id: 9}
  actions/cache@v4: {ref: v4, commit: sha1-` + lockedCache + `, owner_id: 44036562, repo_id: 105467887}
  a/self@v1: {ref: v1, commit: sha1-` + lockedSelf + `, owner_id: 1, repo_id: 10}
  a/sha256@v1: {ref: v1, commit: sha256-abababababababababababababababababababababababababababababababab, owner_id: 1, repo_id: 11}
  a/fail@v1: {ref: v1, commit: sha1-` + lockedFail + `, owner_id: 1, repo_id: 12}
`

func lockedWorkflow(t *testing.T, key string, uses ...string) workflow.WorkflowMapping {
	t.Helper()
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, u := range uses {
		src += "      - uses: " + u + "\n"
	}
	m := parseWorkflow(t, src)
	f, err := lockfile.Parse([]byte(lockedLock))
	require.NoError(t, err)
	m.Lock = f.Workflow(key)
	return m
}

const ciKey = ".github/workflows/ci.yml"

func messages(errs []*diagnostic.Error) []string {
	var out []string
	for _, e := range errs {
		out = append(out, e.Message)
	}
	return out
}

// T1
func TestRule_Locked_TagRootIsFetchedAtTheLockedCommit(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"a/b@" + lockedB: parseActionFile(t, nodeAction),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/b@v1"))
	assert.Empty(t, errs)
	assert.Equal(t, []string{"a/b@" + lockedB}, fetcher.calls)
}

// T2
func TestRule_Locked_SHARootDoesNotReportInnerTags(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"a/sha@" + writtenSHA: parseActionFile(t, "name: X\nruns:\n  using: composite\n  steps:\n    - uses: x/y@v9\n"),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/sha@"+writtenSHA))
	assert.Empty(t, errs)
	assert.Equal(t, []string{"a/sha@" + writtenSHA}, fetcher.calls)
}

// T3
func TestRule_Locked_ReportsDockerInside(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"a/b@" + lockedB: parseActionFile(t, "name: X\nruns:\n  using: composite\n  steps:\n    - uses: x/y@v9\n    - uses: docker://alpine:latest\n"),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/b@v1"))
	assert.Equal(t, []string{`"a/b@v1" uses unpinned Docker action "docker://alpine:latest"`}, messages(errs))
}

// T4
func TestRule_Locked_FollowsTheParentsUses(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"a/two@" + lockedTwo:   parseActionFile(t, "name: X\nruns:\n  using: composite\n  steps:\n    - uses: b/mid@v1\n"),
		"b/mid@" + lockedMid:   parseActionFile(t, "name: X\nruns:\n  using: composite\n  steps:\n    - uses: c/leaf@v1\n"),
		"c/leaf@" + lockedLeaf: parseActionFile(t, dockerInside),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/two@v1"))
	assert.Equal(t, []string{`"a/two@v1" uses unpinned Docker action "docker://alpine:latest" via "b/mid@v1", "c/leaf@v1"`}, messages(errs))
}

// T5
func TestRule_Locked_FollowsTheWorkflowsList(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"a/list@" + lockedList: parseActionFile(t, "name: X\nruns:\n  using: composite\n  steps:\n    - uses: c/d@v2\n"),
		"c/d@" + lockedD:       parseActionFile(t, dockerInside),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/list@v1"))
	assert.Equal(t, []string{`"a/list@v1" uses unpinned Docker action "docker://alpine:latest" via "c/d@v2"`}, messages(errs))
}

// T6
func TestRule_Locked_DoesNotFollowWhatNeitherLocks(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"a/neither@" + lockedNeith: parseActionFile(t, "name: X\nruns:\n  using: composite\n  steps:\n    - uses: e/f@v1\n"),
		"e/f@" + lockedF:           parseActionFile(t, dockerInside),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/neither@v1"))
	assert.Empty(t, errs)
	assert.Equal(t, []string{"a/neither@" + lockedNeith}, fetcher.calls)
}

// T7
func TestRule_Locked_SubPathRootsShareTheirRepositorysEntry(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"actions/cache/restore@" + lockedCache: parseActionFile(t, nodeAction),
		"actions/cache/save@" + lockedCache:    parseActionFile(t, nodeAction),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "actions/cache/restore@v4", "actions/cache/save@v4"))
	assert.Empty(t, errs)
	assert.Equal(t, []string{"actions/cache/restore@" + lockedCache, "actions/cache/save@" + lockedCache}, fetcher.calls)
}

// T8
func TestRule_Locked_SelfRepositoryRefIsFollowedAtTheLockedCommit(t *testing.T) {
	fetcher := &mockFetcher{files: map[string]*ast.File{
		"a/self@" + lockedSelf:     parseActionFile(t, "name: X\nruns:\n  using: composite\n  steps:\n    - uses: $/sub\n"),
		"a/self/sub@" + lockedSelf: parseActionFile(t, dockerInside),
	}}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/self@v1"))
	assert.Equal(t, []string{`"a/self@v1" uses unpinned Docker action "docker://alpine:latest" via "a/self/sub@v1"`}, messages(errs))
}

// T9
func TestRule_Locked_DoesNotFollowSHA256Commits(t *testing.T) {
	fetcher := &mockFetcher{err: fmt.Errorf("must not be called")}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/sha256@v1"))
	assert.Empty(t, errs)
	assert.Empty(t, fetcher.calls)
}

// T10
func TestRule_Locked_FetchErrorNamesTheRefAsWritten(t *testing.T) {
	fetcher := &mockFetcher{err: fmt.Errorf("failed to fetch action.yml for a/fail@%s: HTTP 500", lockedFail)}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "a/fail@v1"))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, `"a/fail@v1"`)
	assert.Contains(t, errs[0].Message, "HTTP 500")
}

// T11
func TestRule_Unlocked_TagRootIsNotFollowed(t *testing.T) {
	fetcher := &mockFetcher{err: fmt.Errorf("must not be called")}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ".github/workflows/other.yml", "a/b@v1"))
	assert.Empty(t, errs)
	assert.Empty(t, fetcher.calls)
}

// T12
func TestRule_Locked_UnlistedRootIsNotFollowed(t *testing.T) {
	fetcher := &mockFetcher{err: fmt.Errorf("must not be called")}
	errs := (&Rule{Fetcher: fetcher}).CheckWorkflow(lockedWorkflow(t, ciKey, "e/f@v1", "x/y@"+writtenSHA))
	assert.Empty(t, errs)
	assert.Empty(t, fetcher.calls)
}
