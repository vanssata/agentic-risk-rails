package e2e

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// taskID is the id `rr task start` printed ("task <id>").
func taskID(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "task ") {
			return strings.TrimSpace(strings.TrimPrefix(l, "task "))
		}
	}
	t.Fatalf("no task id in %q", out)
	return ""
}

func editInput(p *proj, rel string) map[string]any {
	return map[string]any{"file_path": p.abs(rel), "old_string": "<?php", "new_string": "<?php // tweak"}
}

// 1. A light task under Claude: sync, start, hook decisions, a real edit, close.
func TestLightTaskUnderClaude(t *testing.T) {
	p := newProj(t)
	p.mustRR("sync")
	assert.FileExists(t, p.abs(".claude/settings.json"))
	assert.FileExists(t, p.abs(".mcp.json"))
	out := p.mustRR("task", "start", "--goal", "tweak the home page", "--files", lightFile, "--declare", lightDecl)
	assert.Contains(t, out, "-> light")
	id := taskID(t, out)

	for name, tc := range map[string]struct {
		tool  string
		input map[string]any
		allow bool
		msg   string
	}{
		"edit in scope":     {"Edit", editInput(p, lightFile), true, ""},
		"edit out of scope": {"Edit", editInput(p, "src/Payment/PaymentService.php"), false, "scope guard"},
		"agent task close":  {"Bash", map[string]any{"command": "rr task close"}, false, "rr task commands"},
		"read secret":       {"Read", map[string]any{"file_path": p.abs(".env.local")}, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			out, code := p.claudeHook(tc.tool, tc.input)
			if tc.allow {
				assert.Zero(t, code, out)
				assert.Contains(t, out, `"permissionDecision":"allow"`)
				return
			}
			assert.Equal(t, 2, code, out)
			assert.Contains(t, out, tc.msg)
		})
	}

	p.write(lightFile, "<?php // tweak\n")
	out = p.mustRR("task", "close")
	assert.Contains(t, out, "closed")
	assert.FileExists(t, p.abs(".rr/tasks/"+id+".jsonl"), "archived")
	p.mustRR("status")
	p.mustRR("cost", "--task", id)
	assert.Contains(t, p.mustRR("doctor"), "ok")
}

// 6. Dogfooding: the generated files are in sync, until one is touched.
func TestSyncCheckDetectsDrift(t *testing.T) {
	p := newProj(t)
	p.mustRR("sync")
	assert.Contains(t, p.mustRR("sync", "--check"), "ok")
	p.write(".claude/settings.json", p.read(".claude/settings.json")+"\n// drift\n")
	out, code := p.rr("sync", "--check")
	assert.NotZero(t, code, out)
}
