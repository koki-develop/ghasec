package deprecatedcommands_test

import (
	"testing"

	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	deprecatedcommands "github.com/koki-develop/ghasec/rules/deprecated-commands"
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

func parseActionMapping(t *testing.T, src string) workflow.ActionMapping {
	t.Helper()
	f, err := yamlparser.ParseBytes([]byte(src), 0)
	require.NoError(t, err)
	require.NotEmpty(t, f.Docs)
	m, ok := f.Docs[0].Body.(*ast.MappingNode)
	require.True(t, ok)
	return workflow.ActionMapping{Mapping: workflow.Mapping{MappingNode: m}}
}

func TestRule_ID(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	assert.Equal(t, "deprecated-commands", r.ID())
}

func TestRule_Required(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	assert.False(t, r.Required())
}

func TestRule_Online(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	assert.False(t, r.Online())
}

func TestRule_SetEnv(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::set-env name=FOO::bar\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
}

func TestRule_AddPath(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::add-path::/usr/local/bin\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::add-path" must not be used`, errs[0].Message)
}

func TestRule_SetOutput(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::set-output name=result::value\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-output" must not be used`, errs[0].Message)
}

func TestRule_SaveState(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::save-state name=pid::1234\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::save-state" must not be used`, errs[0].Message)
}

func TestRule_MultilineRun(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"hello\"\n          echo \"::set-output name=x::y\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-output" must not be used`, errs[0].Message)
}

func TestRule_ChainedCommand(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: foo && echo \"::set-output name=x::y\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-output" must not be used`, errs[0].Message)
}

func TestRule_PipedCommand(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::set-env name=FOO::bar\" | tee log.txt\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
}

func TestRule_MultipleDeprecated(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"::set-env name=A::1\"\n          echo \"::add-path::/opt\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
	assert.Equal(t, `deprecated workflow command "::add-path" must not be used`, errs[1].Message)
}

func TestRule_SingleQuoted(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '::set-env name=FOO::bar'\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
}

func TestRule_EnvWorkflowLevel(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"ACTIONS_ALLOW_UNSECURE_COMMANDS" must not be enabled`, errs[0].Message)
}

func TestRule_EnvJobLevel(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"ACTIONS_ALLOW_UNSECURE_COMMANDS" must not be enabled`, errs[0].Message)
}

func TestRule_EnvStepLevel(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n        env:\n          ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"ACTIONS_ALLOW_UNSECURE_COMMANDS" must not be enabled`, errs[0].Message)
}

func TestRule_EnvStringTrue(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: \"true\"\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"ACTIONS_ALLOW_UNSECURE_COMMANDS" must not be enabled`, errs[0].Message)
}

func TestRule_EnvCaseInsensitive(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: \"True\"\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"ACTIONS_ALLOW_UNSECURE_COMMANDS" must not be enabled`, errs[0].Message)
}

func TestRule_EnvFalse(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: false\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_EnvNumeric(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: 1\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_EnvYes(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: \"yes\"\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_SafeCommands(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"hello\" >> $GITHUB_ENV\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_NoDeprecatedInRun(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"hello world\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_CommentInShell(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          # echo \"::set-env name=FOO::bar\"\n          echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_PrintfCommand(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: printf \"::set-env name=FOO::bar\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
}

func TestRule_PrintCommand(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: print \"::set-env name=FOO::bar\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
}

func TestRule_UsesStepNoRun(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v6\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_ActionCompositeRun(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - run: echo \"::set-env name=FOO::bar\"\n      shell: bash\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
}

func TestRule_ActionCompositeEnv(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "name: My Action\nruns:\n  using: composite\n  steps:\n    - run: echo hello\n      shell: bash\n      env:\n        ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `"ACTIONS_ALLOW_UNSECURE_COMMANDS" must not be enabled`, errs[0].Message)
}

func TestRule_ActionNonComposite(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "name: My Action\nruns:\n  using: node20\n  main: index.js\n"
	m := parseActionMapping(t, src)
	errs := r.CheckAction(m)
	assert.Empty(t, errs)
}

func TestRule_OrChain(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::add-path::/opt\" || true\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::add-path" must not be used`, errs[0].Message)
}

func TestRule_SemicolonChain(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::set-output name=x::y\"; echo done\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-output" must not be used`, errs[0].Message)
}

func TestRule_Subshell(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: (echo \"::set-env name=FOO::bar\")\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 1)
	assert.Equal(t, `deprecated workflow command "::set-env" must not be used`, errs[0].Message)
}

func TestRule_MixedViolations(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::set-env name=FOO::bar\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	require.Len(t, errs, 2)
}

func TestRule_VariableExpansionSkipped(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"::set-env name=${VAR}::value\"\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}

func TestRule_EnvAbsent(t *testing.T) {
	r := &deprecatedcommands.Rule{}
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
	m := parseMapping(t, src)
	errs := r.CheckWorkflow(m)
	assert.Empty(t, errs)
}
