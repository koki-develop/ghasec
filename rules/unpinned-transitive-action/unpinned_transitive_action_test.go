package unpinnedtransitiveaction

import (
	"context"
	"fmt"
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockFetcher struct {
	files map[string]*ast.File // key: "owner/repo@ref"
	err   error
}

func (m *mockFetcher) FetchActionFile(_ context.Context, owner, repo, ref string) (*ast.File, error) {
	if m.err != nil {
		return nil, m.err
	}
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
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
	assert.Contains(t, errs[0].Message, "failed to fetch action.yml")
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
