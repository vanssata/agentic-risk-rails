package models

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func spec() core.ModelsSpec {
	s := core.StrictDefaults().Models
	s.TiersAllowed = []core.Tier{core.TierFast, core.TierBalanced, core.TierStrong, core.TierExpert}
	s.ByRuntime = map[string]map[core.Tier][]string{"claude": {
		core.TierFast: {"haiku"}, core.TierBalanced: {"sonnet"},
		core.TierStrong: {"opus", "opus-old"}, core.TierExpert: {"fable"},
	}}
	return s
}

func run(t *testing.T, states map[string]core.ModelState, mut func(*core.ModelsSpec)) (core.EffectiveTiers, error) {
	t.Helper()
	s := spec()
	if mut != nil {
		mut(&s)
	}
	return Resolve(context.Background(), Input{
		Spec: s, Runtime: "claude", Account: "a", Cache: Cache{Path: filepath.Join(t.TempDir(), "m.json")},
		Prober: fakes.Prober{RuntimeName: "claude", States: states}, Now: t0,
	})
}

func TestResolveTable(t *testing.T) {
	all := map[string]core.ModelState{"haiku": core.ModelPass, "sonnet": core.ModelPass, "opus": core.ModelPass, "fable": core.ModelPass}
	cases := []struct {
		name   string
		states map[string]core.ModelState
		mut    func(*core.ModelsSpec)
		models map[core.Tier]string
		ladder map[core.Tier]core.Tier
		code   string
	}{
		{"all pass", all, nil,
			map[core.Tier]string{core.TierFast: "haiku", core.TierBalanced: "sonnet", core.TierStrong: "opus", core.TierExpert: "fable"}, map[core.Tier]core.Tier{}, ""},
		{"EXPERT missing", map[string]core.ModelState{"haiku": core.ModelPass, "sonnet": core.ModelPass, "opus": core.ModelPass}, nil,
			map[core.Tier]string{core.TierFast: "haiku", core.TierBalanced: "sonnet", core.TierStrong: "opus"}, map[core.Tier]core.Tier{core.TierExpert: core.TierStrong}, ""},
		{"STRONG+EXPERT missing", map[string]core.ModelState{"haiku": core.ModelPass, "sonnet": core.ModelPass}, nil,
			map[core.Tier]string{core.TierFast: "haiku", core.TierBalanced: "sonnet"}, map[core.Tier]core.Tier{core.TierExpert: core.TierBalanced, core.TierStrong: core.TierBalanced}, ""},
		{"FAST missing", map[string]core.ModelState{"sonnet": core.ModelPass, "opus": core.ModelPass}, nil,
			map[core.Tier]string{core.TierBalanced: "sonnet", core.TierStrong: "opus"}, map[core.Tier]core.Tier{core.TierExpert: core.TierStrong, core.TierFast: core.TierBalanced}, ""},
		{"second candidate used", map[string]core.ModelState{"sonnet": core.ModelPass, "opus-old": core.ModelPass}, nil,
			map[core.Tier]string{core.TierBalanced: "sonnet", core.TierStrong: "opus-old"}, nil, ""},
		{"tier not allowed", all, func(s *core.ModelsSpec) { s.TiersAllowed = []core.Tier{core.TierBalanced} },
			map[core.Tier]string{core.TierBalanced: "sonnet"}, nil, ""},
		{"no BALANCED", map[string]core.ModelState{"haiku": core.ModelPass, "opus": core.ModelPass}, nil,
			map[core.Tier]string{core.TierFast: "haiku", core.TierStrong: "opus"}, nil, "NO_TIER"},
		{"BALANCED unknown is not pass", map[string]core.ModelState{"sonnet": core.ModelUnknown}, nil, map[core.Tier]string{}, nil, "NO_TIER"},
		{"nothing", nil, nil, map[core.Tier]string{}, nil, "NO_TIER"},
		{"BALANCED not allowed", all, func(s *core.ModelsSpec) { s.TiersAllowed = []core.Tier{core.TierFast} },
			map[core.Tier]string{core.TierFast: "haiku"}, nil, "NO_TIER"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			et, err := run(t, c.states, c.mut)
			if c.code == "" {
				require.NoError(t, err)
			} else {
				var r *core.Refusal
				require.True(t, errors.As(err, &r))
				assert.Equal(t, c.code, r.Code)
			}
			assert.Equal(t, c.models, et.Models)
			for k, v := range c.ladder {
				assert.Equal(t, v, et.Ladder[k], k)
			}
			for _, m := range et.Models { // only PASS models
				assert.Equal(t, core.ModelPass, c.states[m])
			}
		})
	}
}

func TestResolveCacheTTLAndUnknownKeepsPrevious(t *testing.T) {
	cache := Cache{Path: filepath.Join(t.TempDir(), "sub", "m.json")}
	in := func(states map[string]core.ModelState, now time.Time) Input {
		s := spec()
		return Input{Spec: s, Runtime: "claude", Account: "a", Cache: cache, Now: now,
			Prober: fakes.Prober{RuntimeName: "claude", States: states}}
	}
	pass := map[string]core.ModelState{"sonnet": core.ModelPass, "haiku": core.ModelPass}
	_, err := Resolve(context.Background(), in(pass, t0))
	require.NoError(t, err)

	// Fresh cache: the prober is not asked (would say FAIL).
	et, err := Resolve(context.Background(), in(map[string]core.ModelState{}, t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.Equal(t, "sonnet", et.Models[core.TierBalanced])

	// Expired: re-probed; UNKNOWN keeps the previous PASS.
	et, err = Resolve(context.Background(), in(map[string]core.ModelState{"sonnet": core.ModelUnknown, "haiku": core.ModelFail}, t0.Add(25*time.Hour)))
	require.NoError(t, err)
	assert.Equal(t, "sonnet", et.Models[core.TierBalanced])
	assert.Empty(t, et.Models[core.TierFast])

	// Refresh forces a probe; a hard FAIL wins.
	i := in(map[string]core.ModelState{"sonnet": core.ModelFail}, t0.Add(26*time.Hour))
	i.Refresh = true
	_, err = Resolve(context.Background(), i)
	assert.Error(t, err)

	// A different account does not see the entries.
	i = in(nil, t0)
	i.Account, i.Prober = "b", nil
	_, err = Resolve(context.Background(), i)
	assert.Error(t, err)
}

func TestResolveOfflineUsesOnlyFreshCache(t *testing.T) {
	cache := Cache{Path: filepath.Join(t.TempDir(), "m.json")}
	require.NoError(t, cache.Put("claude", LocalAccount, core.ProbeResult{Model: "sonnet", State: core.ModelPass, ProbedAt: t0}))
	home := filepath.Dir(cache.Path)
	s := spec()
	s.Probe.Cache = cache.Path
	assert.Contains(t, ForSync(context.Background(), s, home, t0.Add(time.Hour)), "claude")
	assert.NotContains(t, ForSync(context.Background(), s, home, t0.Add(48*time.Hour)), "claude")
}

func TestProberErrorIsFailClosed(t *testing.T) {
	s := spec()
	_, err := Resolve(context.Background(), Input{Spec: s, Runtime: "claude", Account: "a",
		Cache: Cache{Path: filepath.Join(t.TempDir(), "m.json")}, Now: t0, Prober: errProber{}})
	assert.Error(t, err)
}

type errProber struct{}

func (errProber) Runtime() string { return "claude" }
func (errProber) Probe(context.Context, []string) ([]core.ProbeResult, error) {
	return nil, errors.New("boom")
}

func TestCorruptCacheIsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	require.NoError(t, os.WriteFile(p, []byte("{not json"), 0o644))
	_, ok := Cache{Path: p}.Get("claude", "a", "sonnet")
	assert.False(t, ok)
	require.NoError(t, Cache{Path: p}.Put("claude", "a", core.ProbeResult{Model: "sonnet", State: core.ModelPass, ProbedAt: t0}))
	_, ok = Cache{Path: p}.Get("claude", "a", "sonnet")
	assert.True(t, ok)
}

func TestCatalogueSHAStable(t *testing.T) {
	a := map[string]core.ModelState{"sonnet": core.ModelPass}
	e1, _ := run(t, a, nil)
	e2, _ := run(t, a, nil)
	e3, _ := run(t, map[string]core.ModelState{"sonnet": core.ModelPass, "haiku": core.ModelPass}, nil)
	assert.Equal(t, e1.CatalogueSHA, e2.CatalogueSHA)
	assert.NotEqual(t, e1.CatalogueSHA, e3.CatalogueSHA)
}

func TestDegradations(t *testing.T) {
	et, _ := run(t, map[string]core.ModelState{"sonnet": core.ModelPass}, nil)
	var evs []string
	var clamp, extra, halve bool
	for _, d := range Degradations(et) {
		evs = append(evs, d.Event+":"+string(d.Tier))
		clamp, extra, halve = clamp || d.ClampAutonomy, extra || d.ExtraReviewPass, halve || d.HalveScouts
	}
	assert.Equal(t, []string{"tier_missing:EXPERT", "tier_missing:STRONG", "autonomy_clamped:STRONG", "tier_missing:FAST"}, evs)
	assert.True(t, clamp && extra && halve)
	full, _ := run(t, map[string]core.ModelState{"haiku": core.ModelPass, "sonnet": core.ModelPass, "opus": core.ModelPass, "fable": core.ModelPass}, nil)
	assert.Empty(t, Degradations(full))
}

func TestOnError(t *testing.T) {
	et, _ := run(t, map[string]core.ModelState{"haiku": core.ModelPass, "sonnet": core.ModelPass, "opus": core.ModelPass}, nil)
	s := spec()
	off := false
	cases := []struct {
		name     string
		typ      string
		tier     core.Tier
		thinking bool
		attempt  int
		mut      func()
		want     Action
		code     string
	}{
		{"rate limit retries", "rate_limit_error", core.TierStrong, false, 1, nil, Action{Retry: true}, ""},
		{"overloaded retries", "overloaded_error", core.TierStrong, true, 2, nil, Action{Retry: true}, ""},
		{"rate limit exhausted", "rate_limit_error", core.TierStrong, false, 3, nil, Action{}, "QUOTA"},
		{"implementer falls to ladder", "permission_error", core.TierStrong, false, 0, nil, Action{MarkFail: true, Tier: core.TierBalanced}, ""},
		{"not_found scout", "not_found_error", core.TierFast, false, 0, nil, Action{MarkFail: true, Tier: core.TierBalanced}, ""},
		{"thinking never downgrades", "permission_error", core.TierStrong, true, 0, nil, Action{MarkFail: true}, "TIER_LOST"},
		{"thinking may downgrade when off", "permission_error", core.TierStrong, true, 0, func() { s.Ladder.NeverDowngradeThinking = &off }, Action{MarkFail: true, Tier: core.TierBalanced}, ""},
		{"no tier below BALANCED", "permission_error", core.TierBalanced, false, 0, nil, Action{MarkFail: true}, "TIER_LOST"},
		{"unknown type fails closed", "api_error", core.TierStrong, false, 0, nil, Action{}, "TIER_LOST"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mut != nil {
				c.mut()
			}
			a, err := OnError(s, et, c.tier, c.typ, c.thinking, c.attempt)
			assert.Equal(t, c.want, a)
			if c.code == "" {
				assert.NoError(t, err)
				return
			}
			var r *core.Refusal
			require.True(t, errors.As(err, &r))
			assert.Equal(t, c.code, r.Code)
		})
	}
}
