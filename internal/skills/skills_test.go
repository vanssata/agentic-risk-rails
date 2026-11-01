package skills

import (
	"context"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
	rrskills "github.com/vanssata/agentic-risk-rails/skills"
)

var nameRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func TestRenderPerRuntime(t *testing.T) {
	for rt, dir := range Dirs {
		t.Run(rt, func(t *testing.T) {
			files, err := gen{rt, dir}.Render(context.Background(), core.SyncInput{})
			require.NoError(t, err)
			require.Len(t, files, 5)
			var summary []string
			for _, f := range files {
				summary = append(summary, f.Path)
				// Agent Skills spec: name equals the directory, description 1..1024.
				parts := strings.Split(f.Path, "/")
				name := parts[len(parts)-2]
				body := string(f.Content)
				assert.True(t, nameRe.MatchString(name) && len(name) <= 64, name)
				assert.Contains(t, body, "\nname: "+name+"\n")
				m := regexp.MustCompile(`(?m)^description: (.+)$`).FindStringSubmatch(body)
				require.NotNil(t, m, f.Path)
				assert.LessOrEqual(t, len(m[1]), 1024)
				assert.Less(t, strings.Count(body, "\n"), 500)
			}
			sort.Strings(summary)
			testutil.Golden(t, "paths_"+rt+".golden", []byte(strings.Join(summary, "\n")+"\n"))
			for _, f := range files {
				for _, n := range []string{"rr-simplify", "rr-release"} {
					if strings.HasSuffix(f.Path, n+"/SKILL.md") {
						testutil.Golden(t, n+"_"+rt+".golden", f.Content)
					}
				}
			}
		})
	}
}

// errata #53: under the runner the task journal is outside the agent's container,
// so the skills that send the agent to `rr verify --task` say what to do instead.
func TestVerifySkillsKnowTheRunner(t *testing.T) {
	for _, name := range []string{"rr-build", "rr-ship"} {
		b, err := fs.ReadFile(rrskills.FS, name+"/SKILL.md")
		require.NoError(t, err)
		assert.Contains(t, string(b), "`$RR_LEVEL` is L2 or higher", name)
	}
}
