package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/guard"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
	"github.com/vanssata/agentic-risk-rails/internal/wiring"
)

// P0 integration: real policy resolver + real guard on the php-symfony fixture.
func TestWiredGuardOnFixture(t *testing.T) {
	restore := policy.SetCeilingPaths(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "none"))
	defer restore()
	repo := testutil.CopyFixture(t, "php-symfony")
	ctx := context.Background()

	gc, err := wiring.GuardContext(ctx, repo, "claude")
	require.NoError(t, err)
	assert.Equal(t, core.L1, gc.Level)
	require.NotNil(t, gc.Loader)
	require.NotNil(t, gc.Differ)

	orig, err := os.ReadFile(filepath.Join(repo, "riskrails.yaml"))
	require.NoError(t, err)
	policyPath := filepath.Join(repo, "riskrails.yaml")
	g := guard.New()
	check := func(c core.ToolCall) core.Verdict { return g.Check(ctx, c, gc) }

	loosen := strings.Replace(string(orig), "ceiling: L2", "ceiling: L4", 1)
	require.NotEqual(t, string(orig), loosen)
	v := check(core.ToolCall{Tool: "Write", Paths: []string{policyPath}, Content: loosen})
	assert.Equal(t, core.Deny, v.Decision, v.Reason)

	tighten := strings.Replace(string(orig), "ceiling: L2", "ceiling: L1", 1)
	v = check(core.ToolCall{Tool: "Write", Paths: []string{policyPath}, Content: tighten})
	assert.Equal(t, core.Allow, v.Decision, v.Reason)

	v = check(core.ToolCall{Tool: "Bash", Command: "git push --force origin main"})
	assert.Equal(t, core.Deny, v.Decision, v.Reason)
	v = check(core.ToolCall{Tool: "Bash", Command: "php bin/phpunit tests/Payment"})
	assert.Equal(t, core.Allow, v.Decision, v.Reason)
	v = check(core.ToolCall{Tool: "Read", Paths: []string{filepath.Join(repo, ".env.prod")}})
	assert.Equal(t, core.Deny, v.Decision, v.Reason)

	// sync input resolves the same effective policy.
	in, err := syncInput(ctx, repo)
	require.NoError(t, err)
	assert.Equal(t, gc.Policy.PolicySHA, in.Policy.PolicySHA)
}

func TestWiredGuardDeniesUnparsablePolicy(t *testing.T) {
	restore := policy.SetCeilingPaths(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "none"))
	defer restore()
	repo := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "schema: 1\nautonomy: {ceilling: L4}\n"})
	_, err := wiring.GuardContext(context.Background(), repo, "claude")
	assert.Error(t, err, "rr guard denies when the context cannot be built")
}
