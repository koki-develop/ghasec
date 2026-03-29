package broadsecretenv_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	broadsecretenv "github.com/koki-develop/ghasec/rules/broad-secret-env"
	"github.com/koki-develop/ghasec/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseMapping(t *testing.T, src string) workflow.WorkflowMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	require.NotEmpty(t, f.Docs)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.WorkflowMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_ID(t *testing.T) {
	r := &broadsecretenv.Rule{}
	assert.Equal(t, "broad-secret-env", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &broadsecretenv.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &broadsecretenv.Rule{}
	assert.False(t, r.Online())
}

func TestRule_WorkflowEnvSecrets(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  TOKEN: ${{ secrets.GITHUB_TOKEN }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "secrets must not")
	assert.Contains(t, errs[0].Message, "workflow-level")
}

func TestRule_WorkflowEnvGithubToken(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  TOKEN: ${{ github.token }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "github.token must not")
	assert.Contains(t, errs[0].Message, "workflow-level")
}

func TestRule_JobEnvSecrets(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      TOKEN: ${{ secrets.DEPLOY_KEY }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "secrets must not")
	assert.Contains(t, errs[0].Message, "job-level")
}

func TestRule_JobEnvGithubToken(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      GH_TOKEN: ${{ github.token }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "github.token must not")
	assert.Contains(t, errs[0].Message, "job-level")
}

func TestRule_StepEnvSecrets_NoError(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_StepEnvGithubToken_NoError(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          GH_TOKEN: ${{ github.token }}\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_NoExpression_NoError(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  FOO: hello\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_NonSecretExpression_NoError(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  REF: ${{ github.ref }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_GithubNonTokenProperty_NoError(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  SHA: ${{ github.sha }}\n  REPO: ${{ github.repository }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_NoEnv_NoError(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	assert.Empty(t, errs)
}

func TestRule_EmbeddedInString(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  AUTH: \"Bearer ${{ secrets.TOKEN }}\"\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "workflow-level")
}

func TestRule_MultipleSecretsInOneEnv(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  CREDS: \"${{ secrets.USER }}:${{ secrets.PASS }}\"\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_MultipleEnvVars(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  A: ${{ secrets.A }}\n  B: ${{ secrets.B }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_WorkflowAndJobBoth(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  A: ${{ secrets.A }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      B: ${{ secrets.B }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
	assert.Contains(t, errs[0].Message, "workflow-level")
	assert.Contains(t, errs[1].Message, "job-level")
}

func TestRule_MultipleJobs(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      TOKEN: ${{ secrets.TOKEN }}\n    steps:\n      - run: echo hi\n  b:\n    runs-on: ubuntu-latest\n    env:\n      TOKEN: ${{ secrets.TOKEN }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_IndexAccessSecrets(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  TOKEN: ${{ secrets['TOKEN'] }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "workflow-level")
}

func TestRule_IndexAccessGithubToken(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  TOKEN: ${{ github['token'] }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "github.token must not")
	assert.Contains(t, errs[0].Message, "workflow-level")
}

func TestRule_SecretInBinaryExpression(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\nenv:\n  TOKEN: ${{ secrets.TOKEN || '' }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 1)
}

func TestRule_SecretsInFunctionArgs(t *testing.T) {
	r := &broadsecretenv.Rule{}
	src := "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      CREDS: ${{ format('{0}:{1}', secrets.USER, secrets.PASS) }}\n    steps:\n      - run: echo hi\n"
	errs := r.CheckWorkflow(parseMapping(t, src))
	require.Len(t, errs, 2)
}

func TestRule_Explainer(t *testing.T) {
	r := &broadsecretenv.Rule{}
	assert.NotEmpty(t, r.Why())
	assert.NotEmpty(t, r.Fix())
}
