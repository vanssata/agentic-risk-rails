package autonomy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
)

// R2: secrets in the checkout (git-ignored included) are masked in the agent and
// in the close sandbox.
func TestSecretsInTheCheckoutAreMasked(t *testing.T) {
	root := repo(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".env.local"), []byte("S=1"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "config", "secrets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "config", "secrets", "k.pem"), []byte("k"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "src", "deep"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "src", "deep", ".env"), []byte("S=1"), 0o600))
	d := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t), NoRead: []string{".env*", "config/secrets/**", "~/.ssh/**"}}

	args, err := d.argv(root, "n", "none", true, nil)
	require.NoError(t, err)
	j := " " + strings.Join(args, " ") + " "
	assert.Contains(t, j, " type=bind,src=/dev/null,dst=/work/.env.local,readonly ")
	assert.Contains(t, j, " type=bind,src=/dev/null,dst=/work/src/deep/.env,readonly ")
	assert.Contains(t, j, " type=tmpfs,dst=/work/config/secrets,tmpfs-size=4096,readonly ")
	assert.NotContains(t, j, "dst=/work/a.txt")

	cargs, err := d.CommandArgv("true")
	require.NoError(t, err)
	assert.Contains(t, strings.Join(cargs, " "), "dst=/work/.env.local,readonly", "the close sandbox masks them too")
}

// R4 + R1: ceilings and the codex trust config reach the container read-only.
func TestCeilingsAndCodexTrustAreMounted(t *testing.T) {
	root := repo(t)
	st := t.TempDir()
	for _, n := range []string{CodexConfigName, CeilingEntName, CeilingUserName} {
		require.NoError(t, os.WriteFile(filepath.Join(st, n), []byte("x"), 0o600))
	}
	d := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t), Runtime: "codex",
		CodexConfig: filepath.Join(st, CodexConfigName), CeilingEnt: filepath.Join(st, CeilingEntName), CeilingUser: filepath.Join(st, CeilingUserName)}
	args, err := d.argv(root, "n", "none", true, nil)
	require.NoError(t, err)
	j := " " + strings.Join(args, " ") + " "
	assert.Contains(t, j, ",dst=/etc/riskrails/ceiling.yaml,readonly ")
	assert.Contains(t, j, ",dst=/tmp/.config/riskrails/ceiling.yaml,readonly ")
	assert.Contains(t, j, ",dst=/tmp/.codex/config.toml,readonly ")
	assert.Contains(t, j, " /tmp/.codex:rw,mode=0700,uid=")

	d.Runtime = "claude"
	args, err = d.argv(root, "n", "none", true, nil)
	require.NoError(t, err)
	assert.NotContains(t, strings.Join(args, " "), ".codex")

	d.CeilingEnt, d.CeilingUser = filepath.Join(st, "absent"), ""
	args, err = d.argv(root, "n", "none", true, nil)
	require.NoError(t, err)
	assert.NotContains(t, strings.Join(args, " "), "ceiling.yaml", "absent ceilings are not mounted")
}

func TestRunnerWritesContainerConfig(t *testing.T) {
	e := newEnv(t)
	e.rt.ID = "codex"
	e.r.Gens = []core.Generator{fakes.Generator{ID: "g", Files: []core.File{
		{Path: ".codex/hooks.json", Content: []byte(`rr guard`)}, {Path: ".codex/config.toml", Content: []byte(`default_permissions = "rr"`)}}}}
	e.r.Ceilings = func() (*core.Layer, *core.Layer, error) {
		return &core.Layer{Raw: []byte("ent: 1\n")}, nil, nil
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.Equal(t, "ent: 1\n", string(mustRead(t, filepath.Join(e.r.StateDir, CeilingEntName))))
	assert.NoFileExists(t, filepath.Join(e.r.StateDir, CeilingUserName))
	assert.Contains(t, string(mustRead(t, filepath.Join(e.r.StateDir, CodexConfigName))), `[projects."/work"]`)
	assert.Contains(t, string(mustRead(t, filepath.Join(e.r.StateDir, CodexConfigName))), `trust_level = "trusted"`)
}

// R5: a runtime outside project.runtimes would run without its config.
func TestRuntimeOutsideProjectRuntimesIsRefused(t *testing.T) {
	e := newEnv(t)
	e.pol.Project.Runtimes = []string{"codex"}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "RUNTIME", e.refusal(t, err).Code)
	assert.Zero(t, e.worker.calls)
}

// R1: no hook / profile in the render, no agent.
func TestRenderWithoutHookFilesIsRefused(t *testing.T) {
	e := newEnv(t)
	e.r.Gens = []core.Generator{fakes.Generator{ID: "g", Files: []core.File{{Path: ".claude/settings.json", Content: []byte(`{}`)}}}}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "RENDER", e.refusal(t, err).Code)
	assert.Zero(t, e.worker.calls)

	e = newEnv(t)
	e.rt.ID = "codex"
	e.r.Gens = []core.Generator{fakes.Generator{ID: "g", Files: []core.File{{Path: ".codex/hooks.json", Content: []byte(`rr guard`)}}}}
	_, err = e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "RENDER", e.refusal(t, err).Code, "codex also needs its permission profile")
}

// R3: triage of the real files (not the declared mode) decides before the agent.
func TestTriageOfRealFilesSkipsBeforeTheAgent(t *testing.T) {
	for name, w := range map[string]core.Weight{
		"full":         {Mode: core.ModeFull},
		"guarded":      {Mode: core.ModeGuarded},
		"irreversible": {Mode: core.ModeLight, Irreversible: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.r.Start = func(context.Context, Task) (core.Weight, error) { return w, nil }
			out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x", Files: []string{"src/Tax/a.php"}}})
			require.NoError(t, err)
			require.Len(t, out, 1)
			assert.Equal(t, "skipped", out[0].Status)
			assert.Zero(t, e.worker.calls)
			assert.Empty(t, e.host.Opened)
		})
	}
	e := newEnv(t)
	e.r.Start = func(context.Context, Task) (core.Weight, error) { return core.Weight{Mode: core.ModeLight}, nil }
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x", Files: []string{"a.txt"}}})
	require.NoError(t, err)
	assert.Equal(t, "pr", out[0].Status)
}
