package research

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

const sha1 = "abc1234"

func load(t *testing.T, name string) Report {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	r, err := Parse(string(b))
	require.NoError(t, err)
	return r
}

func TestParse(t *testing.T) {
	r := load(t, "scout_a.txt")
	assert.Len(t, r.Facts, 4)
	assert.Equal(t, "[V]", r.Facts[0].Tag)
	assert.Equal(t, []string{"src/Order/OrderService.php:42"}, r.Facts[0].Sources)
	assert.Equal(t, int64(52000), r.Tokens)
	assert.Equal(t, 11, r.Calls)

	for name, bad := range map[string]string{
		"unknown section": "WAT:\n- x",
		"bad fact":        "FACTS:\n- only claim",
		"bad tag":         "FACTS:\n- a | b | [X]",
		"bullet outside":  "- x",
		"bad cost":        "COST: lots",
	} {
		_, err := Parse(bad)
		assert.Error(t, err, name)
	}
}

func TestMergeGolden(t *testing.T) {
	m := Merge([]Report{load(t, "scout_a.txt"), load(t, "scout_b.txt")})
	// duplicate merged, sources joined, [V] wins
	require.NotEmpty(t, m.Facts)
	assert.Equal(t, "[V]", m.Facts[0].Tag)
	assert.Len(t, m.Facts[0].Sources, 1) // same normalized source (case, :line)
	assert.Len(t, m.Conflicts, 2)        // number (30 vs 60) and polarity (retries)
	out, err := MergeBrief(m, MaxBriefTokens)
	require.NoError(t, err)
	testutil.Golden(t, "merge.golden", []byte(out))
}

func TestMergeNeverJoinsDifferentPolarityOrNumbers(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		conflicts  int
		facts      int
	}{
		{"identical", "the cache is warm on boot", "the cache is warm on boot", 0, 1},
		{"polarity", "the cache is warm on boot", "the cache is never warm on boot", 1, 0},
		{"numbers", "the cache holds 100 entries", "the cache holds 200 entries", 1, 0},
		{"unrelated", "the cache is warm on boot", "queue workers restart nightly", 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := []Report{
				{Facts: []Fact{{tc.a, []string{"x"}, "[V]"}}},
				{Facts: []Fact{{tc.b, []string{"y"}, "[V]"}}},
			}
			m := Merge(rs)
			assert.Len(t, m.Conflicts, tc.conflicts)
			assert.Len(t, m.Facts, tc.facts)
		})
	}
}

func TestNormSource(t *testing.T) {
	assert.Equal(t, NormSource("SRC/A.php:12"), NormSource("src/a.php"))
	assert.Equal(t, NormSource("https://x.dev/doc/#frag"), NormSource("http://x.dev/doc"))
}

func TestRolesForMode(t *testing.T) {
	spec := core.StrictDefaults().Research
	for mode, want := range map[core.Mode]int{
		core.ModeLight: 0, core.ModeGuarded: 2, core.ModeFull: 5, core.ModeFullIrreversible: 5, core.ModeProgramme: 6,
	} {
		got, err := RolesFor(spec, mode)
		require.NoError(t, err, mode)
		assert.Len(t, got, want, mode)
	}
	_, err := RolesFor(core.ResearchSpec{ByMode: map[core.Mode][]string{core.ModeFull: {"nope"}}}, core.ModeFull)
	assert.Error(t, err)
}

func TestBriefEveryRoleWithin3k(t *testing.T) {
	var known []string
	for i := 0; i < 2000; i++ {
		known = append(known, fmt.Sprintf("known fact number %d about the payment module", i))
	}
	for _, role := range Roles {
		b, err := Brief(role, "find callers of charge", known, 80000)
		require.NoError(t, err, role)
		assert.LessOrEqual(t, EstimateTokens(b), MaxBriefTokens, role)
		for _, part := range []string{"GOAL:", "ALREADY KNOWN", "TOOLS AND SOURCES:", "BOUNDARIES:", "FACTS:", "COST:"} {
			assert.Contains(t, b, part, role)
		}
	}
	_, err := Brief("bogus", "g", nil, 1)
	assert.Error(t, err)
	_, err = Brief("code", strings.Repeat("goal ", 5000), nil, 1)
	assert.Error(t, err)
}

func TestMergeBriefTruncates(t *testing.T) {
	var fs []Fact
	for i := 0; i < 500; i++ {
		fs = append(fs, Fact{fmt.Sprintf("distinct%d alpha%d beta%d gamma%d delta%d", i, i, i, i, i), []string{"s"}, "[U]"})
	}
	out, err := MergeBrief(Merged{Facts: fs}, MaxBriefTokens)
	require.NoError(t, err)
	assert.LessOrEqual(t, EstimateTokens(out), MaxBriefTokens)
	assert.Contains(t, out, "FACTS-OMITTED")
}

func TestCacheInvalidationPerRole(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := Entry{Read: []string{"src/a.php", "vendor/x"}, LockHash: "L1", At: t0}
	same := Inv{Changed: []string{"unrelated.txt"}, LockHash: "L1", Now: t0.Add(time.Hour)}
	for _, tc := range []struct {
		role         string
		inv          func(Inv) Inv
		validAtStart bool
		invalidated  bool
	}{
		{"code", func(i Inv) Inv { i.Changed = []string{"src/a.php"}; return i }, true, true},
		{"test", func(i Inv) Inv { i.Changed = []string{"vendor/x/y.php"}; return i }, true, true},
		{"tech-docs", func(i Inv) Inv { i.LockHash = "L2"; return i }, true, true},
		{"prior-art", func(i Inv) Inv { i.Now = t0.Add(8 * 24 * time.Hour); return i }, true, true},
		{"project-docs", func(i Inv) Inv { i.Changed = []string{"docs/adr/0001.md"}; return i }, true, true},
		{"history", func(i Inv) Inv { return i }, false, true},
	} {
		t.Run(tc.role, func(t *testing.T) {
			e := base
			e.Role = tc.role
			assert.Equal(t, tc.validAtStart, Valid(e, same), "unchanged")
			assert.False(t, Valid(e, tc.inv(same)), "changed")
		})
	}
	assert.False(t, Valid(Entry{Role: "unknown"}, same))
}

func TestCachePutGet(t *testing.T) {
	dir := t.TempDir()
	q := QHash("q")
	e := Entry{SHA: sha1, Role: "code", QHash: q, Body: "FACTS:\n", Read: []string{"a"}, At: time.Now()}
	_, ok, err := Get(dir, sha1, "code", q, Inv{})
	require.NoError(t, err)
	assert.False(t, ok)
	require.NoError(t, Put(dir, e))
	got, ok, err := Get(dir, sha1, "code", q, Inv{})
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "FACTS:\n", got.Body)
	_, ok, _ = Get(dir, sha1, "code", q, Inv{Changed: []string{"a"}})
	assert.False(t, ok)
	// keys cannot escape the cache dir
	_, _, err = Get(dir, "../../etc", "code", q, Inv{})
	assert.Error(t, err)
	assert.Error(t, Put(dir, Entry{SHA: sha1, Role: "../x", QHash: q}))
}

func TestRepoDir(t *testing.T) {
	d := RepoDir("~/.cache/riskrails/research/<repo-hash>", "/home/u", "/r")
	assert.True(t, strings.HasPrefix(d, "/home/u/.cache/riskrails/research/"))
	assert.NotContains(t, d, "<repo-hash>")
}

// roleRunner answers per role and counts calls.
type roleRunner struct {
	mu    sync.Mutex
	calls map[string]int
	body  map[string]string
}

func (r *roleRunner) Run(_ context.Context, s core.WorkerSpec) (core.WorkerReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[s.Role]++
	b, ok := r.body[s.Role]
	if !ok {
		return core.WorkerReport{Status: core.StatusBlocked}, nil
	}
	return core.WorkerReport{Status: core.StatusDone, Body: b}, nil
}

func TestRunUsesCache(t *testing.T) {
	spec := core.StrictDefaults().Research
	body := "FACTS:\n- a b c | s | [V]\nREAD:\n- src/a.php\nCOST: tokens=1 calls=1\n"
	rr := &roleRunner{calls: map[string]int{}, body: map[string]string{"code-scout": body, "test-scout": body}}
	dir := t.TempDir()
	req := Request{SHA: sha1, Question: "q", Goal: "g", Mode: core.ModeGuarded, Inv: Inv{Now: time.Now()}}

	res, err := Run(context.Background(), rr, dir, spec, req)
	require.NoError(t, err)
	assert.Len(t, res.Reports, 2)
	assert.Equal(t, 0, res.CacheHits)
	assert.Equal(t, "code", res.Reports[0].Role)

	res, err = Run(context.Background(), rr, dir, spec, req)
	require.NoError(t, err)
	assert.Equal(t, 2, res.CacheHits)
	assert.Equal(t, 1, rr.calls["code-scout"])

	req.Inv.Changed = []string{"src/a.php"} // READ touched: code and test rerun
	_, err = Run(context.Background(), rr, dir, spec, req)
	require.NoError(t, err)
	assert.Equal(t, 2, rr.calls["code-scout"])

	req.Mode = core.ModeFull // other scouts return BLOCKED
	_, err = Run(context.Background(), rr, dir, spec, req)
	assert.Error(t, err)
}
