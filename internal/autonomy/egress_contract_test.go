package autonomy

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEgressContract runs the real proxy (RR_CONTRACT=1, RR_PROXY_IMAGE and
// RR_AGENT_IMAGE pinned by digest, present locally) and probes it from a
// container on the internal network the way the agent sits there. Needs network.
func TestEgressContract(t *testing.T) {
	if os.Getenv("RR_CONTRACT") != "1" {
		t.Skip("set RR_CONTRACT=1, RR_PROXY_IMAGE and RR_AGENT_IMAGE to run against real docker and squid")
	}
	proxyImg, agentImg := os.Getenv("RR_PROXY_IMAGE"), os.Getenv("RR_AGENT_IMAGE")
	require.NotEmpty(t, proxyImg)
	require.NotEmpty(t, agentImg)
	e := Egress{Image: proxyImg, Dir: t.TempDir(), Hosts: []string{"api.anthropic.com"}}
	require.NoError(t, e.With(t.Context(), func(n *EgressNet) error {
		// curl exit 0 with an HTTP code; the CONNECT status shows in %{http_connect}
		probe := func(proxy, url string) string {
			args := []string{"run", "--rm", "--pull", "never", "--network", n.Network, agentImg,
				"curl", "-sS", "-o", "/dev/null", "--max-time", "15", "-w", "%{http_connect}"}
			if proxy != "" {
				args = append(args, "--proxy", proxy)
			}
			out, err := exec.CommandContext(t.Context(), "docker", append(args, url)...).CombinedOutput()
			if err != nil {
				return "fail:" + strings.TrimSpace(string(out))
			}
			return strings.TrimSpace(string(out))
		}
		// squid needs a moment to listen
		for i := 0; i < 20 && strings.HasPrefix(probe(n.ProxyURL, "https://api.anthropic.com/"), "fail:"); i++ {
			_ = exec.Command("sleep", "0.5").Run()
		}
		assert.Equal(t, "200", probe(n.ProxyURL, "https://api.anthropic.com/"), "allowed host tunnels")
		assert.Contains(t, probe(n.ProxyURL, "https://example.com/"), "403", "unlisted host refused")
		assert.Contains(t, probe(n.ProxyURL, "https://1.1.1.1/"), "403", "IP literal refused")
		assert.Contains(t, probe("", "https://api.anthropic.com/"), "fail:", "no route without the proxy")
		return nil
	}))
}
