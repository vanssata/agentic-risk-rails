package guard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
)

// loadFixturePolicy is the tiny local loader: yaml.v3 over StrictDefaults(), so
// absent fields keep their strict defaults (internal/policy is not in this tree).
func loadFixturePolicy(t testing.TB) core.Policy {
	t.Helper()
	b, err := os.ReadFile("../../testdata/php-symfony/riskrails.yaml")
	require.NoError(t, err)
	p := core.StrictDefaults()
	require.NoError(t, yaml.Unmarshal(b, &p))
	return p
}

func effective(p core.Policy) core.EffectivePolicy {
	return core.EffectivePolicy{Policy: p, InForce: p, PolicySHA: "test"}
}

type corpusCase struct {
	Name      string            `json:"name"`
	Level     core.Level        `json:"level"`
	Tool      string            `json:"tool"`
	Command   string            `json:"command"`
	Paths     []string          `json:"paths"`
	Content   string            `json:"content"`
	URL       string            `json:"url"`
	Model     string            `json:"model"`
	Cwd       string            `json:"cwd"`
	StepFiles []string          `json:"step_files"`
	Symlinks  map[string]string `json:"symlinks"`
	Files     []string          `json:"files"`
	Protected []string          `json:"protected"` // extra protected_paths for this case
	Policy    string            `json:"policy"` // riskrails.yaml diff: LOOSEN | TIGHTEN | MIXED | ERROR | PARSE_ERROR | NIL
	Fixture   core.Decision     `json:"fixture"`
	Strict    core.Decision     `json:"strict"`
	Rule      string            `json:"rule"` // substring of Verdict.Rule, optional
}

func (c corpusCase) run(t *testing.T, name string, p core.Policy, want core.Decision) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	home := filepath.Join(t.TempDir(), "home")
	require.NoError(t, os.MkdirAll(home, 0o755))
	sub := strings.NewReplacer("{root}", root, "{home}", home)
	for link, target := range c.Symlinks {
		l := filepath.Join(root, link)
		require.NoError(t, os.MkdirAll(filepath.Dir(l), 0o755))
		require.NoError(t, os.Symlink(sub.Replace(target), l))
	}
	for _, f := range c.Files {
		require.NoError(t, os.MkdirAll(filepath.Dir(sub.Replace(f)), 0o755))
		require.NoError(t, os.WriteFile(sub.Replace(f), nil, 0o644))
	}
	call := core.ToolCall{Runtime: "test", Event: "PreToolUse", Tool: c.Tool, Command: sub.Replace(c.Command),
		Content: c.Content, URL: c.URL, Model: c.Model, Cwd: sub.Replace(c.Cwd)}
	for _, p := range c.Paths {
		call.Paths = append(call.Paths, sub.Replace(p))
	}
	p.Enforcement.ProtectedPaths = append(append([]string{}, p.Enforcement.ProtectedPaths...), c.Protected...)
	gc := core.GuardContext{Policy: effective(p), Level: c.Level, Root: root, Home: home,
		Tiers: core.EffectiveTiers{Models: map[core.Tier]string{core.TierFast: "claude-haiku-4-5", core.TierBalanced: "sonnet", core.TierStrong: "claude-opus-5-5"}}}
	if c.StepFiles != nil {
		gc.StepFiles = []string{}
		for _, f := range c.StepFiles {
			gc.StepFiles = append(gc.StepFiles, sub.Replace(f))
		}
	}
	switch c.Policy {
	case "":
	case "NIL":
	case "PARSE_ERROR":
		gc.Loader, gc.Differ = fakes.Loader{Err: errors.New("bad yaml")}, fakes.Differ{Dir: core.Equal}
	case "ERROR":
		gc.Loader, gc.Differ = fakes.Loader{Out: p}, fakes.Differ{Err: errors.New("boom")}
	default:
		gc.Loader, gc.Differ = fakes.Loader{Out: p}, fakes.Differ{Dir: core.Direction(c.Policy), Changes: []core.FieldChange{{Path: "enforcement.commands.allow", Direction: core.Direction(c.Policy)}}}
	}
	v := New().Check(context.Background(), call, gc)
	assert.Equal(t, want, v.Decision, "%s: %s (rule %q, reason %q)", name, c.Name, v.Rule, v.Reason)
	if c.Rule != "" {
		assert.Contains(t, v.Rule, c.Rule, c.Name)
	}
	assert.NotEmpty(t, v.Reason+v.Rule, "verdict must say why")
}

func TestCorpus(t *testing.T) {
	files, err := filepath.Glob("testdata/corpus/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	fixture, strict := loadFixturePolicy(t), core.StrictDefaults()
	total := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		var cases []corpusCase
		require.NoError(t, json.Unmarshal(b, &cases), f)
		total += len(cases)
		for _, c := range cases {
			require.NotEmpty(t, c.Fixture, "%s/%s needs fixture", f, c.Name)
			require.NotEmpty(t, c.Strict, "%s/%s needs strict", f, c.Name)
			t.Run(filepath.Base(f)+"/"+c.Name, func(t *testing.T) {
				c.run(t, "fixture", fixture, c.Fixture)
				c.run(t, "strict", strict, c.Strict)
			})
		}
	}
	assert.GreaterOrEqual(t, total, 150, "corpus must hold at least 150 cases")
}

func TestCheckFailClosed(t *testing.T) {
	gc := core.GuardContext{Policy: effective(core.StrictDefaults()), Root: t.TempDir()}
	t.Run("cancelled context denies", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.Equal(t, core.Deny, New().Check(ctx, core.ToolCall{Tool: "Bash", Command: "git status"}, gc).Decision)
	})
	t.Run("expired deadline denies", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		assert.Equal(t, core.Deny, New().Check(ctx, core.ToolCall{Tool: "Bash", Command: "git status"}, gc).Decision)
	})
	t.Run("panic denies", func(t *testing.T) {
		// a Differ that panics, reached through a policy-file edit
		gc := gc
		gc.Loader, gc.Differ = fakes.Loader{}, panicDiffer{}
		call := core.ToolCall{Tool: "Write", Content: "x", Paths: []string{filepath.Join(gc.Root, "riskrails.yaml")}}
		v := New().Check(context.Background(), call, gc)
		assert.Equal(t, core.Deny, v.Decision)
		assert.Contains(t, v.Reason, "internal error")
	})
	t.Run("empty tool denies", func(t *testing.T) {
		assert.Equal(t, core.Deny, New().Check(context.Background(), core.ToolCall{}, gc).Decision)
	})
}

type panicDiffer struct{}

func (panicDiffer) Diff(core.Policy, core.Policy, []string) (core.Direction, []core.FieldChange, error) {
	panic("differ exploded")
}

func TestMatchCommand(t *testing.T) {
	w := func(s string) []word {
		var out []word
		for _, f := range strings.Fields(s) {
			out = append(out, word{s: f})
		}
		return out
	}
	for _, c := range []struct {
		pat, cmd string
		want     bool
	}{
		{"git status", "git status", true},
		{"git status", "git status -s", false},
		{"git diff*", "git diff --stat", true},
		{"php bin/phpunit*", "php bin/phpunit --filter X", true},
		{"git push --force*", "git push --force origin", true},
		{"git push --force*", "git push origin --force-with-lease", true},
		{"git push --force*", "git push origin -f", true},
		{"git push --force*", "git push origin main", false},
		{"git push * main", "git push origin main", true},
		{"rm -rf /", "rm -fr /", true},
		{"rm -rf /", "rm -r -f /", true},
		{"rm -rf /", "rm -rf /tmp/x", false},
		{"composer global *", "composer global require x/y", true},
		{"git push*", "git push", true},
	} {
		assert.Equal(t, c.want, matchCommand(c.pat, w(c.cmd)), "%q vs %q", c.pat, c.cmd)
	}
}

func TestMatchPath(t *testing.T) {
	for _, c := range []struct {
		pat, rel string
		want     bool
	}{
		{".env*", ".env.local", true},
		{".env*", "app/.env", false},
		{"config/secrets/**", "config/secrets/a/b", true},
		{"config/secrets/**", "config/other", false},
		{".github/**", ".github/workflows/ci.yml", true},
		{"riskrails.yaml", "riskrails.yaml", true},
		{"riskrails.yaml", "sub/riskrails.yaml", false},
		{"src/*.php", "src/a/b.php", false},
	} {
		assert.Equal(t, c.want, matchPath(c.pat, c.rel), "%q vs %q", c.pat, c.rel)
	}
}

// FuzzCheck: the guard never panics and only returns allow/ask/deny.
func FuzzCheck(f *testing.F) {
	for _, s := range []string{"git status", "bash -c 'rm -rf /'", "eval $(echo hi)", "cat <<EOF\n$(id)\nEOF", "a=b c; {", "$'\\x67it' push", "curl http://[::1", "git -c alias.x=!id x", "cp a b > /etc/x", "((", "`", "\x00"} {
		f.Add(s, uint8(0))
		f.Add(s, uint8(2))
	}
	root := f.TempDir()
	fixture := loadFixturePolicy(f)
	g := New()
	f.Fuzz(func(t *testing.T, cmd string, lvl uint8) {
		gc := core.GuardContext{Policy: effective(fixture), Level: core.Level(lvl % 5), Root: root, Home: "/home/x",
			Loader: fakes.Loader{Out: fixture}, Differ: fakes.Differ{Dir: core.Tighten}}
		for _, call := range []core.ToolCall{
			{Tool: "Bash", Command: cmd},
			{Tool: "Write", Paths: []string{filepath.Join(root, cmd)}, Content: cmd},
			{Tool: "Read", Paths: []string{cmd}},
			{Tool: "WebFetch", URL: cmd},
			{Tool: "Agent", Model: cmd},
		} {
			v := g.Check(context.Background(), call, gc)
			if v.Decision != core.Allow && v.Decision != core.Ask && v.Decision != core.Deny {
				t.Fatalf("invalid decision %q for %q", v.Decision, cmd)
			}
			if gc.Level >= core.L2 && v.Decision == core.Ask {
				t.Fatalf("ask at L2+ for %q", cmd)
			}
		}
	})
}

// BenchmarkCheck measures typical commands; p99 is reported as a metric.
func BenchmarkCheck(b *testing.B) {
	root := b.TempDir()
	fixture := loadFixturePolicy(b)
	gc := core.GuardContext{Policy: effective(fixture), Level: core.L1, Root: root, Home: "/home/x"}
	g := New()
	cmds := []string{"git status", "php bin/phpunit --filter FooTest", "composer install && php bin/console cache:clear",
		"git diff HEAD~1 | head -50", `bash -c "cd src && php bin/phpunit tests/Unit"`, "curl -s https://packagist.org/packages/list.json -o /tmp/x"}
	lat := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		g.Check(context.Background(), core.ToolCall{Tool: "Bash", Command: cmds[i%len(cmds)]}, gc)
		lat = append(lat, time.Since(start))
	}
	b.StopTimer()
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		b.ReportMetric(float64(lat[len(lat)*99/100].Microseconds()), "p99_us")
	}
}
