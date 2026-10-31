package guard

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Egress is a tripwire (DES §14.7): hosts are read from literal arguments of
// known network commands. `curl $URL`, interpreters and test code escape it;
// the sandbox network allowlist is the boundary.

var (
	schemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	scpRe    = regexp.MustCompile(`^(?:[\w.-]+@)?([\w.-]+\.[A-Za-z]{2,}|localhost):[^:]`)
	bareRe   = regexp.MustCompile(`^(?:[\w-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:/.*)?$|^localhost(?::\d+)?(?:/.*)?$|^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/.*)?$`)
)

var (
	httpTools   = opts("curl", "wget", "http", "https", "xh", "aria2c")
	installers  = opts("composer", "npm", "pnpm", "yarn", "pip", "pip3", "pipx", "uv", "gem", "go", "cargo", "bundle", "brew")
	remoteShell = opts("ssh", "scp", "sftp", "rsync")
	rawSockets  = opts("nc", "ncat", "telnet", "socat", "ftp")
	gitNet      = opts("clone", "fetch", "pull", "push", "ls-remote", "remote", "submodule")
	// options whose next word is a value, not a target; per tool because -i, -H, -p differ.
	valueFlags = map[string]map[string]bool{
		"curl":  opts("-o", "-H", "-d", "-X", "-A", "-u", "-e", "-b", "-c", "-F", "-T", "-m", "-x", "-w", "-K", "--output", "--header", "--data", "--data-raw", "--data-binary", "--request", "--user", "--user-agent", "--referer", "--cookie", "--form", "--upload-file", "--proxy", "--max-time"),
		"wget":  opts("-O", "-o", "-P", "-e", "-U", "-t", "-T", "-w", "-i", "-B", "--output-document", "--directory-prefix", "--user-agent", "--header", "--post-data"),
		"ssh":   opts("-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-W"),
		"scp":   opts("-P", "-i", "-l", "-o", "-F", "-J", "-c", "-S"),
		"sftp":  opts("-P", "-i", "-l", "-o", "-F", "-J", "-c", "-S", "-b"),
		"rsync": opts("-e", "--rsh", "--port", "--exclude", "--include", "--files-from"),
	}
)

// found collects the hosts of one invocation; unresolved means some target
// could not be determined statically.
type found struct {
	hosts      []string
	unresolved bool
}

func (f *found) addURL(raw string) {
	if h := hostOfURL(raw); h != "" {
		f.hosts = append(f.hosts, h)
	} else {
		f.unresolved = true
	}
}

// hostsOf returns the hosts an invocation contacts and whether some target
// could not be resolved statically.
func hostsOf(argv []word) ([]string, bool) {
	var f found
	name, args := argv[0].s, argv[1:]
	switch {
	case httpTools[name]:
		f.httpTool(name, args)
	case name == "git":
		f.gitRemote(args)
	case installers[name]:
		for _, w := range args {
			if hs := urlLike(strings.TrimPrefix(w.s, "git+")); hs != "" {
				f.hosts = append(f.hosts, hs)
			}
		}
	case remoteShell[name]:
		f.remoteShell(name, args)
	case rawSockets[name]:
		for _, w := range args {
			if w.dyn {
				f.unresolved = true
			} else if !strings.HasPrefix(w.s, "-") {
				f.hosts = append(f.hosts, strings.ToLower(w.s))
				break
			}
		}
	}
	return f.hosts, f.unresolved
}

func (f *found) httpTool(name string, args []word) {
	skip := false
	for _, w := range args {
		switch {
		case skip:
			skip = false
		case w.dyn:
			f.unresolved = true
		case strings.HasPrefix(w.s, "-"):
			skip = valueFlags[name][w.s]
		case schemeRe.MatchString(w.s):
			f.addURL(w.s)
		case bareRe.MatchString(w.s):
			f.addURL("http://" + w.s)
		}
	}
}

func (f *found) gitRemote(args []word) {
	if len(args) == 0 || !gitNet[args[0].s] {
		return
	}
	for _, w := range args[1:] {
		if w.dyn && args[0].s == "clone" {
			f.unresolved = true
		} else if hs := urlLike(w.s); hs != "" {
			f.hosts = append(f.hosts, hs)
		}
	}
}

func (f *found) remoteShell(name string, args []word) {
	skip, first := false, true
	for _, w := range args {
		switch {
		case skip:
			skip = false
		case w.dyn:
			f.unresolved = true
		case strings.HasPrefix(w.s, "-"):
			skip = valueFlags[name][w.s]
		case schemeRe.MatchString(w.s):
			f.addURL(w.s)
		case name == "ssh" || name == "sftp":
			if first {
				f.hosts = append(f.hosts, stripUser(w.s))
			}
			first = false
		default:
			if m := scpRe.FindStringSubmatch(w.s); m != nil {
				f.hosts = append(f.hosts, strings.ToLower(m[1]))
			} else if i := strings.IndexByte(w.s, ':'); i > 0 && !strings.ContainsAny(w.s[:i], "/.") {
				f.hosts = append(f.hosts, strings.ToLower(stripUser(w.s[:i])))
			}
		}
	}
}

func stripUser(s string) string {
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(strings.Trim(s, "[]"))
}

// urlLike returns the host of an argument that is a URL or scp-style address.
func urlLike(s string) string {
	if schemeRe.MatchString(s) {
		return hostOfURL(s)
	}
	if m := scpRe.FindStringSubmatch(s); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

func hostOfURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// checkHost applies egress.allow / deny_default to one host ("" = unknown).
func checkHost(host, raw string, e core.EnforcementSpec, gc core.GuardContext) core.Verdict {
	if e.Egress.DenyDefault != nil && !*e.Egress.DenyDefault {
		return core.Verdict{Decision: core.Allow}
	}
	if host != "" {
		for _, pat := range e.Egress.Allow {
			if globWord(strings.ToLower(pat), host) {
				return core.Verdict{Decision: core.Allow, Reason: "host allowed", Rule: "enforcement.egress.allow: " + pat}
			}
		}
	}
	if host == "" {
		host = "unknown (" + raw + ")"
	}
	return core.Verdict{Decision: askOrDeny(gc), Reason: "egress to " + host + " is not in egress.allow", Rule: "enforcement.egress.deny_default"}
}

// sameModel is true for equal names, or when one is a family alias ("sonnet")
// and the other a full ID of that family ("claude-sonnet-5-5"). Runtimes pass
// aliases in Agent calls while the effective tiers may hold IDs.
func sameModel(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == b {
		return true
	}
	isAlias := func(x string) bool { return x != "" && !strings.ContainsAny(x, "-.") }
	famOf := func(alias, id string) bool {
		return id == "claude-"+alias || strings.HasPrefix(id, "claude-"+alias+"-")
	}
	return (isAlias(a) && famOf(a, b)) || (isAlias(b) && famOf(b, a))
}

// checkModel enforces DES §4.5(c): an explicit subagent model must be one of the
// effective tiers' models; no model means the session model is inherited.
func checkModel(call core.ToolCall, gc core.GuardContext) core.Verdict {
	if call.Model == "" {
		return core.Verdict{Decision: core.Allow, Reason: "model inherited"}
	}
	if len(gc.Tiers.Models) == 0 { // tiers not resolved (yet): cannot verify
		return core.Verdict{Decision: askOrDeny(gc), Reason: "explicit model " + call.Model + " but no effective tiers to check against", Rule: "models.effective_tiers"}
	}
	for _, m := range gc.Tiers.Models {
		if sameModel(m, call.Model) {
			return core.Verdict{Decision: core.Allow, Reason: "model in effective tiers"}
		}
	}
	return core.Verdict{Decision: core.Deny, Reason: "model " + call.Model + " is not in the effective tiers", Rule: "models.effective_tiers"}
}

// checkPolicyFile decides edits of riskrails.yaml by file tools. It is checked
// before protected_paths, which normally lists the same file: the diff decides.
// The returned verdict is final (scope guard does not apply to a tightening).
func checkPolicyFile(call core.ToolCall, gc core.GuardContext) (core.Verdict, bool) {
	hit := false
	for _, p := range call.Paths {
		if isPolicyFile(resolve(p, call.Cwd, gc)) {
			hit = true
		}
	}
	if !hit {
		return core.Verdict{}, false
	}
	rule := "enforcement.protected_paths: " + policyFile
	d := func(reason string) (core.Verdict, bool) {
		return core.Verdict{Decision: core.Deny, Reason: reason, Rule: rule}, true
	}
	if len(call.Paths) != 1 {
		return d("riskrails.yaml edited together with other files")
	}
	if call.Content == "" {
		return d("riskrails.yaml deletion or empty content denied")
	}
	if gc.Loader == nil || gc.Differ == nil {
		return d("riskrails.yaml edit denied: no policy loader/differ available")
	}
	cand, err := gc.Loader.Parse([]byte(call.Content))
	if err != nil {
		return d("riskrails.yaml edit denied: invalid policy: " + err.Error())
	}
	dir, changes, err := gc.Differ.Diff(gc.Policy.InForce, cand, gc.RepoFiles)
	if err != nil {
		return d("riskrails.yaml edit denied: policy diff failed: " + err.Error())
	}
	if dir.Loosens() {
		var fields []string
		for _, c := range changes {
			if c.Direction.Loosens() {
				fields = append(fields, c.Path)
			}
		}
		return d("riskrails.yaml edit loosens policy (" + string(dir) + ") " + strings.Join(fields, ", "))
	}
	reason := "policy tightened; task becomes full"
	if dir == core.Equal {
		reason = "policy unchanged"
	}
	return core.Verdict{Decision: core.Allow, Reason: reason, Rule: rule}, true
}
