// Package skills renders the runtime-neutral SKILL.md sources into the skill
// directory each confirmed runtime scans (docs/research/verified/mcp.md).
package skills

import (
	"context"
	"io/fs"
	"path"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	src "github.com/vanssata/agentic-risk-rails/skills"
)

// Dirs maps runtime to the repo-relative skills directory it scans.
var Dirs = map[string]string{
	"claude": ".claude/skills",
	"codex":  ".agents/skills",
}

type gen struct{ runtime, dir string }

func (g gen) Name() string { return "skills-" + g.runtime }

func (g gen) Render(_ context.Context, _ core.SyncInput) ([]core.File, error) {
	paths, err := fs.Glob(src.FS, "*/SKILL.md")
	if err != nil {
		return nil, err
	}
	var out []core.File
	for _, p := range paths {
		b, err := src.FS.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, core.File{Path: path.Join(g.dir, p), Content: b})
	}
	return out, nil
}

func init() {
	for rt, dir := range Dirs {
		rrsync.Register(gen{rt, dir})
	}
}
