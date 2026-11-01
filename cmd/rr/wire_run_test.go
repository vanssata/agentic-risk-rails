package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

func TestRunHostingNeedsCeilingRemote(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "ceiling.yaml")
	restore := policy.SetCeilingPaths(filepath.Join(dir, "none"), user)
	defer restore()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "evil/repo")
	_, err := runHosting(context.Background(), dir)
	require.ErrorContains(t, err, "no remote pinned")

	require.NoError(t, os.WriteFile(user, []byte("remote: acme/shop\n"), 0o600))
	h, err := runHosting(context.Background(), dir)
	require.NoError(t, err)
	require.NotNil(t, h)
}

// Opus round 3: rr run refuses L≥2 when the live ruleset is missing (DES §3.4 step 4).
func TestRunRefusesWithoutLiveRuleset(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "ceiling.yaml")
	require.NoError(t, os.WriteFile(user, []byte("remote: acme/shop\n"), 0o600))
	restore := policy.SetCeilingPaths(filepath.Join(dir, "none"), user)
	defer restore()
	prevRun, prevNew := runHosting, newHosting
	defer func() { runHosting, newHosting = prevRun, prevNew }()
	h := fakePR{Hosting: &fakes.Hosting{}}
	runHosting = func(context.Context, string) (core.Hosting, error) { return h, nil }
	newHosting = func(string) (prHosting, error) { return h, nil }
	q := filepath.Join(dir, "q.yaml")
	require.NoError(t, os.WriteFile(q, []byte("- {id: t1, brief: do it}\n"), 0o644))
	_, err := runRR("run", "--queue", q, "--image", "img", "--root", t.TempDir())
	require.ErrorContains(t, err, "L>=2 refused")
}
