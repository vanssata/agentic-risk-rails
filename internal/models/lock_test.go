package models

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func TestLockRoundTripDeterministic(t *testing.T) {
	root := t.TempDir()
	et := core.EffectiveTiers{Runtime: "claude",
		Models: map[core.Tier]string{core.TierStrong: "opus", core.TierBalanced: "sonnet", core.TierFast: "haiku"},
		Ladder: map[core.Tier]core.Tier{core.TierExpert: core.TierStrong}}
	require.NoError(t, WriteLock(root, et))
	a, _ := os.ReadFile(LockPath(root))
	require.NoError(t, WriteLock(root, et))
	b, _ := os.ReadFile(LockPath(root))
	assert.Equal(t, a, b)
	assert.NotContains(t, string(a), "probed")

	got, err := FromLock(spec(), root, "claude")
	require.NoError(t, err)
	assert.Equal(t, et.Models, got.Models)
	assert.Equal(t, core.TierStrong, got.Ladder[core.TierExpert])
	assert.Contains(t, ForSync(context.Background(), spec(), root), "claude")
}

func TestLockIsValidatedAgainstPolicy(t *testing.T) {
	root := t.TempDir()
	// Hand-edited lock: a model that is no candidate, and a tier that is not allowed.
	require.NoError(t, WriteLock(root, core.EffectiveTiers{Runtime: "claude", Models: map[core.Tier]string{
		core.TierBalanced: "sonnet", core.TierFast: "evil-model", core.TierStrong: "opus"}}))
	s := spec()
	s.TiersAllowed = []core.Tier{core.TierFast, core.TierBalanced}
	et, err := FromLock(s, root, "claude")
	require.NoError(t, err)
	assert.Equal(t, map[core.Tier]string{core.TierBalanced: "sonnet"}, et.Models)

	// BALANCED replaced by a non-candidate: NO_TIER, runtime omitted from sync.
	require.NoError(t, os.WriteFile(LockPath(root), []byte(`{"claude":{"models":{"BALANCED":"gpt-evil"},"ladder":{}}}`), 0o644))
	_, err = FromLock(spec(), root, "claude")
	var r *core.Refusal
	require.True(t, errors.As(err, &r))
	assert.Equal(t, "NO_TIER", r.Code)
	assert.Empty(t, ForSync(context.Background(), spec(), root))
}

func TestLockMissingCorruptOrRemoved(t *testing.T) {
	root := t.TempDir()
	_, err := FromLock(spec(), root, "claude")
	assert.Error(t, err)
	require.NoError(t, os.MkdirAll(root+"/.rr", 0o755))
	require.NoError(t, os.WriteFile(LockPath(root), []byte("{bad"), 0o644))
	_, err = FromLock(spec(), root, "claude")
	assert.Error(t, err)

	// A runtime that lost BALANCED is removed from the lock.
	require.NoError(t, WriteLock(root, core.EffectiveTiers{Runtime: "claude", Models: map[core.Tier]string{core.TierBalanced: "sonnet"}}))
	require.NoError(t, WriteLock(root, core.EffectiveTiers{Runtime: "claude", Models: map[core.Tier]string{core.TierFast: "haiku"}}))
	_, err = FromLock(spec(), root, "claude")
	assert.Error(t, err)
}
