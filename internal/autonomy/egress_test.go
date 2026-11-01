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
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestSquidConfAllowsOnlyListedHostsOnConnect(t *testing.T) {
	c, err := squidConf([]string{"API.anthropic.com", "packagist.org", "api.anthropic.com", "github.com"})
	require.NoError(t, err)
	assert.Contains(t, c, "acl allowed dstdomain api.anthropic.com github.com packagist.org\n")
	assert.Contains(t, c, "http_access deny ipliteral\nacl allowed", "IP literals are denied before the allowlist")
	assert.Contains(t, c, "acl ipliteral dstdom_regex")
	assert.Contains(t, c, "http_access allow CONNECT SSL_ports allowed\nhttp_access deny all\n")
	assert.NotContains(t, c, "http_access allow all")
	for _, bad := range []string{"", "a b.com", "x.com\nhttp_access allow all", "https://x.com", "localhost", "*.x.com",
		"169.254.169.254", "1.2.3.4", "0x7f.1", ".co.uk", ".github.io", ".github.com", "[::1]", "::1"} {
		_, err := squidConf([]string{"api.anthropic.com", bad})
		assert.Error(t, err, bad)
	}
	_, err = squidConf(nil)
	assert.Error(t, err, "empty allowlist")
}

func TestRuntimeHosts(t *testing.T) {
	assert.Equal(t, []string{"api.anthropic.com"}, RuntimeHosts("claude"))
	assert.Equal(t, []string{"api.openai.com"}, RuntimeHosts("codex"))
	assert.Empty(t, RuntimeHosts("gemini"))
}

func fakeDocker(t *testing.T, failOn string) string {
	log := filepath.Join(t.TempDir(), "calls")
	testutil.FakeBin(t, "docker", `echo "$@" >> `+log+`
case "$*" in *"`+failOn+`"*) [ -n "`+failOn+`" ] && { echo boom >&2; exit 1; } ;; esac
exit 0`)
	return log
}

func TestEgressUpTopologyAndDown(t *testing.T) {
	log := fakeDocker(t, "")
	e := Egress{Image: testImage, Hosts: RuntimeHosts("claude"), Dir: t.TempDir()}
	n, err := e.Up(t.Context())
	require.NoError(t, err)
	b, _ := os.ReadFile(log)
	j := string(b)
	assert.Contains(t, j, "network create --internal "+n.Network)
	assert.Contains(t, j, "--pull never")
	assert.Contains(t, j, "--name "+strings.TrimPrefix(strings.TrimSuffix(n.ProxyURL, ":3128"), "http://")+" --network "+n.Network)
	assert.Contains(t, j, "network connect rr-out-")
	assert.NotContains(t, j, "--network bridge")
	assert.NotContains(t, j, "--network host")
	assert.Contains(t, j, "dst=/etc/squid/squid.conf,readonly")
	n.Down()
	b, _ = os.ReadFile(log)
	assert.Contains(t, string(b), "rm -f rr-proxy-")
	assert.Contains(t, string(b), "network rm "+n.Network+" rr-out-")
	m, _ := filepath.Glob(filepath.Join(e.Dir, "squid-*.conf"))
	assert.Empty(t, m, "conf removed")
}

func TestEgressUpFailureCleansUpAndNeverFallsBack(t *testing.T) {
	for _, failOn := range []string{"network create --internal", "run -d", "network connect"} {
		log := fakeDocker(t, failOn)
		_, err := Egress{Image: testImage, Hosts: RuntimeHosts("claude"), Dir: t.TempDir()}.Up(t.Context())
		require.Error(t, err, failOn)
		b, _ := os.ReadFile(log)
		assert.Contains(t, string(b), "network rm", failOn)
		assert.Contains(t, string(b), "rm -f rr-proxy-", failOn)
	}
}

func TestEgressRefusals(t *testing.T) {
	log := fakeDocker(t, "")
	_, err := Egress{Image: "squid:latest", Hosts: RuntimeHosts("claude"), Dir: t.TempDir()}.Up(t.Context())
	assert.Error(t, err, "unpinned proxy image")
	_, err = Egress{Image: testImage, Hosts: []string{"bad host"}, Dir: t.TempDir()}.Up(t.Context())
	assert.Error(t, err)
	b, _ := os.ReadFile(log)
	assert.Empty(t, string(b), "docker not touched")
}

func TestEgressWithCleansUpOnEveryExit(t *testing.T) {
	for name, fn := range map[string]func(*EgressNet) error{
		"ok":     func(*EgressNet) error { return nil },
		"halt":   func(*EgressNet) error { return &core.Refusal{Code: "HALT"} },
		"budget": func(*EgressNet) error { return &core.Refusal{Code: "BUDGET"} },
		"error":  func(*EgressNet) error { return assert.AnError },
	} {
		log := fakeDocker(t, "")
		_ = Egress{Image: testImage, Hosts: RuntimeHosts("codex"), Dir: t.TempDir()}.With(t.Context(), fn)
		b, _ := os.ReadFile(log)
		assert.Contains(t, string(b), "network rm rr-int-", name)
		assert.Contains(t, string(b), "rm -f rr-proxy-", name)
	}
	log := fakeDocker(t, "")
	assert.Panics(t, func() {
		_ = Egress{Image: testImage, Hosts: RuntimeHosts("codex"), Dir: t.TempDir()}.With(t.Context(), func(*EgressNet) error { panic("x") })
	})
	b, _ := os.ReadFile(log)
	assert.Contains(t, string(b), "network rm rr-int-", "panic")

	// a cancelled run context still removes the proxy
	ctx, cancel := context.WithCancel(t.Context())
	log = fakeDocker(t, "")
	_ = Egress{Image: testImage, Hosts: RuntimeHosts("codex"), Dir: t.TempDir()}.With(ctx, func(*EgressNet) error { cancel(); return ctx.Err() })
	b, _ = os.ReadFile(log)
	assert.Contains(t, string(b), "network rm rr-int-", "cancelled")
}

func TestEgressCleanupFailureIsReported(t *testing.T) {
	fakeDocker(t, "network rm")
	var warns []string
	n, err := Egress{Image: testImage, Hosts: RuntimeHosts("claude"), Dir: t.TempDir(), Warn: func(m string) { warns = append(warns, m) }}.Up(t.Context())
	require.NoError(t, err)
	n.Down()
	require.Len(t, warns, 1)
	assert.Contains(t, warns[0], "boom")
}
