package simplify

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func repo(t *testing.T) string {
	return testutil.GitRepo(t, map[string]string{
		"a.go":         "package a\n",
		"b.go":         "package b\n",
		"skip.go":      "// simplify-ignore\npackage s\n",
		"sgconfig.yml": "ruleDirs: [rules]\n",
	})
}

func TestMissingToolsAreSkipped(t *testing.T) {
	dir := repo(t)
	t.Setenv("PATH", t.TempDir())
	r := Run(context.Background(), dir, []string{"a.go", "skip.go"})
	assert.Equal(t, []string{"a.go"}, r.Files)
	assert.Equal(t, []string{"skip.go"}, r.Ignored)
	require.Len(t, r.Tools, 2)
	for _, tl := range r.Tools {
		assert.Equal(t, "skipped: not installed", tl.Status, tl.Name)
		assert.Empty(t, tl.Findings)
	}
}

func TestFakeTools(t *testing.T) {
	testutil.FakeBin(t, "jscpd", `while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done
cat > "$out/jscpd-report.json" <<'J'
{"duplicates":[
 {"lines":12,"firstFile":{"name":"a.go","start":3},"secondFile":{"name":"b.go","start":7}},
 {"lines":9,"firstFile":{"name":"x.go","start":1},"secondFile":{"name":"y.go","start":1}}]}
J
exit 1`)
	testutil.FakeBin(t, "ast-grep", `echo '{"file":"a.go","ruleId":"no-todo","message":"remove","range":{"start":{"line":4}}}'`)
	r := Run(context.Background(), repo(t), []string{"a.go"})
	require.Len(t, r.Tools, 2)
	assert.Equal(t, "ok", r.Tools[0].Status)
	assert.Equal(t, []Finding{{File: "a.go", Line: 3, Message: "12 duplicated lines with b.go:7"}}, r.Tools[0].Findings)
	assert.Equal(t, []Finding{{File: "a.go", Line: 5, Message: "no-todo: remove"}}, r.Tools[1].Findings)
}

func TestAstGrepNeedsConfig(t *testing.T) {
	testutil.FakeBin(t, "ast-grep", "exit 0")
	dir := testutil.GitRepo(t, map[string]string{"a.go": "package a\n"})
	assert.Equal(t, "skipped: no sgconfig.yml", astGrep(context.Background(), dir, []string{"a.go"}).Status)
}
