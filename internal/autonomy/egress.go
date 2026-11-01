package autonomy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Egress is the proxy the agent container reaches the runtime API through
// (errata #28, owner decision of wave 4): the agent sits on an --internal
// docker network (no gateway) with nothing but a Squid CONNECT allowlist; only
// the proxy also sits on a network with a way out. See docs/research/verified/runner.md.
type Egress struct {
	Bin   string       // default "docker"
	Image string       // squid image pinned by digest; must be present locally
	Hosts []string     // runtime API hosts ∪ enforcement.egress.allow
	Dir   string       // runner-owned directory for squid.conf (outside the checkout)
	Warn  func(string) // cleanup failures; nil = dropped
}

// EgressNet is a running proxy. Down removes it and both networks.
type EgressNet struct {
	Network  string // the internal network the agent joins
	ProxyURL string
	Down     func()
}

// RuntimeHosts are the hosts a runtime's CLI needs with API-key auth.
func RuntimeHosts(runtime string) []string {
	switch runtime {
	case "claude":
		return []string{"api.anthropic.com"}
	case "codex":
		return []string{"api.openai.com"}
	}
	return nil
}

// ValidHostRegex is the squid regex (POSIX ERE, used with -i) a CONNECT target must match.
const ValidHostRegex = `^([a-z0-9-]+\.)+[a-z][a-z0-9-]*$`

// hostRe: exact DNS names of two or more labels. A leading dot (subdomain
// wildcard) is refused: `.github.io` or `.co.uk` would allow every tenant of a
// public suffix. A numeric last label rejects IPv4 literals. ASSUMPTION: list exact hosts.
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
var numericTLD = regexp.MustCompile(`\.[0-9]+$`)

// squidConf allows CONNECT to port 443 of the listed hosts and nothing else.
func squidConf(hosts []string) (string, error) {
	set := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if !hostRe.MatchString(h) || numericTLD.MatchString(h) {
			return "", fmt.Errorf("egress: %q is not a plain host name", h)
		}
		set[h] = true
	}
	if len(set) == 0 {
		return "", fmt.Errorf("egress: no hosts to allow")
	}
	var list []string
	for h := range set {
		list = append(list, h)
	}
	sort.Strings(list)
	// Only names whose last label starts with a letter pass (case-insensitive): every
	// IP form (dotted, hex, octal, IPv6) fails it, so dstdomain never reverse-resolves
	// an IP whose PTR record the attacker controls. [U] not run against a real squid.
	return "http_port 3128\nacl validhost dstdom_regex -i " + ValidHostRegex + "\nhttp_access deny !validhost\nacl allowed dstdomain " + strings.Join(list, " ") + "\nacl SSL_ports port 443\nacl CONNECT method CONNECT\n" +
		"http_access allow CONNECT SSL_ports allowed\nhttp_access deny all\naccess_log none\ncache deny all\n", nil
}

func (e Egress) docker(ctx context.Context, args ...string) error {
	bin := e.Bin
	if bin == "" {
		bin = "docker"
	}
	var errb bytes.Buffer
	c := exec.CommandContext(ctx, bin, args...)
	c.Stderr = &errb
	if err := c.Run(); err != nil {
		return fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// Up starts the networks and the proxy. Any failure removes what was created and
// returns the error: there is no fallback to an open network.
func (e Egress) Up(ctx context.Context) (_ *EgressNet, err error) {
	if !imageRe.MatchString(e.Image) {
		return nil, fmt.Errorf("egress: proxy image %q must be pinned by digest (name@sha256:<64 hex>)", e.Image)
	}
	conf, err := squidConf(e.Hosts)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(e.Dir, 0o700); err != nil {
		return nil, err
	}
	id := randHex()
	confPath := filepath.Join(e.Dir, "squid-"+id+".conf")
	if strings.Contains(confPath, ",") {
		return nil, fmt.Errorf("egress: path %q contains a comma", confPath)
	}
	// 0644: squid starts as root with --cap-drop ALL (no CAP_DAC_OVERRIDE) and cannot
	// read a 0600 file of the host user; the conf holds only the host allowlist.
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil { //nolint:gosec // no secret, see above
		return nil, err
	}
	in, out, proxy := "rr-int-"+id, "rr-out-"+id, "rr-proxy-"+id
	down := func() { // runs on every exit, also after the run's context was cancelled
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		for _, a := range [][]string{{"rm", "-f", proxy}, {"network", "rm", in, out}} {
			if err := e.docker(c, a...); err != nil && e.Warn != nil {
				e.Warn("egress cleanup: " + err.Error())
			}
		}
		_ = os.Remove(confPath)
	}
	defer func() {
		if err != nil {
			down()
		}
	}()
	steps := [][]string{
		{"network", "create", "--internal", in},
		{"network", "create", out},
		{"run", "-d", "--rm", "--pull", "never", "--name", proxy, "--network", in,
			"--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--security-opt", "no-new-privileges",
			"--mount", "type=bind,src=" + confPath + ",dst=/etc/squid/squid.conf,readonly",
			"--entrypoint", "squid", e.Image, "-N", "-f", "/etc/squid/squid.conf"},
		{"network", "connect", out, proxy},
	}
	for _, s := range steps {
		if err = e.docker(ctx, s...); err != nil {
			return nil, fmt.Errorf("egress proxy: %w", err)
		}
	}
	return &EgressNet{Network: in, ProxyURL: "http://" + proxy + ":3128", Down: down}, nil
}

// With runs fn with a live proxy and removes it afterwards on every exit
// (return, error such as a HALT or BUDGET refusal, or panic).
func (e Egress) With(ctx context.Context, fn func(*EgressNet) error) error {
	n, err := e.Up(ctx)
	if err != nil {
		return err
	}
	defer n.Down()
	return fn(n)
}
