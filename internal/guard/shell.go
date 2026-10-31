package guard

import (
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const maxDepth = 5 // nested `bash -c` strings

// cmd is one simple command after normalisation. forms[0] is the outermost
// (e.g. `sudo rm -rf /`), the last is the innermost command that really runs.
// deny and ask lists see every form; allow and unlisted see only the last.
// passthrough marks `bash -c "<str>"`: the inner string is analysed separately.
type cmd struct {
	forms       [][]word
	passthrough bool
	xargs       bool   // stdin appends unknown arguments
	cwd         string // working directory when the command runs ("" = repo root)
}

func (c cmd) last() []word { return c.forms[len(c.forms)-1] }

type redirect struct {
	target word
	write  bool
	cwd    string
}

// analysis is everything statically known about a shell string.
type analysis struct {
	cmds    []cmd
	redirs  []redirect
	unrecog []string
	cwd     string   // tracked working directory
	dirs    []string // pushd stack
	lost    bool     // cwd no longer statically known
}

var (
	braceList   = regexp.MustCompile(`\{[^{}]*(,|\.\.)[^{}]*\}`)
	stdDirs     = map[string]bool{"/bin": true, "/usr/bin": true, "/usr/local/bin": true, "/sbin": true, "/usr/sbin": true, "/opt/homebrew/bin": true}
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	dangerEnv   = map[string]bool{"PATH": true, "BASH_ENV": true, "ENV": true, "IFS": true, "SHELLOPTS": true, "BASHOPTS": true, "PS4": true, "PROMPT_COMMAND": true, "CDPATH": true, "GLOBIGNORE": true, "NODE_OPTIONS": true, "PHPRC": true, "PHP_INI_SCAN_DIR": true, "PYTHONPATH": true, "PYTHONSTARTUP": true, "RUBYOPT": true, "PERL5OPT": true, "EDITOR": true, "VISUAL": true, "PAGER": true}
	unresolvers = map[string]bool{"eval": true, "source": true, ".": true, "alias": true, "trap": true, "fc": true}
	shells      = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "ash": true}
)

func dangerousEnv(name string) bool {
	return dangerEnv[name] || strings.HasPrefix(name, "GIT_") || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_")
}

func analyze(src, cwd string, depth int) *analysis {
	a := &analysis{cwd: cwd}
	a.run(src, depth)
	return a
}

func (a *analysis) run(src string, depth int) {
	if depth > maxDepth {
		a.unrecog = append(a.unrecog, "shell string nested too deeply")
		return
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		a.unrecog = append(a.unrecog, "shell syntax not parseable: "+err.Error())
		return
	}
	var visit func(syntax.Node) bool
	visit = func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Subshell:
			a.scoped(func() { a.walkStmts(x.Stmts, visit) })
			return false
		case *syntax.CmdSubst:
			a.scoped(func() { a.walkStmts(x.Stmts, visit) })
			return false
		case *syntax.ProcSubst:
			a.scoped(func() { a.walkStmts(x.Stmts, visit) })
			return false
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll { // each side runs in its own process
				a.scoped(func() { syntax.Walk(x.X, visit) })
				a.scoped(func() { syntax.Walk(x.Y, visit) })
				return false
			}
		case *syntax.Stmt:
			for _, r := range x.Redirs {
				a.redirect(r)
			}
		case *syntax.CallExpr:
			a.call(x, depth)
		case *syntax.DeclClause:
			for _, as := range x.Args {
				if as.Name != nil && dangerousEnv(as.Name.Value) {
					a.unrecog = append(a.unrecog, "assignment to "+as.Name.Value)
				}
			}
		case *syntax.FuncDecl:
			a.unrecog = append(a.unrecog, "function definition")
		}
		return true
	}
	syntax.Walk(f, visit)
}

func (a *analysis) walkStmts(stmts []*syntax.Stmt, v func(syntax.Node) bool) {
	for _, s := range stmts {
		syntax.Walk(s, v)
	}
}

// scoped runs f in a child process scope: cd/pushd inside do not leak out.
func (a *analysis) scoped(f func()) {
	cwd, dirs, lost := a.cwd, a.dirs, a.lost
	f()
	a.cwd, a.dirs, a.lost = cwd, dirs, lost
}

// chdir updates the tracked working directory for cd/pushd/popd. A target that
// is not static makes every later relative path unresolvable (unrecognised).
func (a *analysis) chdir(argv []word) {
	var dir string
	static := false
	for _, w := range argv[1:] {
		if w.s == "--" || w.s == "-L" || w.s == "-P" {
			continue
		}
		if static || w.dyn || w.glob || w.s == "-" || strings.HasPrefix(w.s, "+") {
			static = false
			break
		}
		dir, static = w.s, true
	}
	switch argv[0].s {
	case "popd":
		if n := len(a.dirs); n > 0 && len(argv) == 1 {
			a.cwd, a.dirs = a.dirs[n-1], a.dirs[:n-1]
			return
		}
		static = false
	case "pushd":
		a.dirs = append(append([]string(nil), a.dirs...), a.cwd)
	}
	if !static {
		if !a.lost {
			a.unrecog = append(a.unrecog, argv[0].s+": working directory not static")
		}
		a.lost = true
		return
	}
	if strings.HasPrefix(dir, "/") || strings.HasPrefix(dir, "~") {
		a.cwd = dir
	} else {
		a.cwd = path.Join(a.cwd, dir)
	}
}

func (a *analysis) redirect(r *syntax.Redirect) {
	if r.Word == nil {
		return
	}
	w := wordOf(r.Word)
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		a.addRedirect(w, true)
	case syntax.DplOut:
		if !isFD(w.s) {
			a.addRedirect(w, true)
		}
	case syntax.RdrIn:
		a.addRedirect(w, false)
	}
}

func isFD(s string) bool {
	if s == "-" {
		return true
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func (a *analysis) addRedirect(w word, write bool) {
	if w.dyn || w.glob {
		a.unrecog = append(a.unrecog, "redirect target not static")
		return
	}
	a.redirs = append(a.redirs, redirect{target: w, write: write, cwd: a.cwd})
}

func (a *analysis) call(c *syntax.CallExpr, depth int) {
	for _, as := range c.Assigns {
		if as.Name != nil && dangerousEnv(as.Name.Value) {
			a.unrecog = append(a.unrecog, "assignment to "+as.Name.Value)
		}
	}
	if len(c.Args) == 0 {
		return
	}
	argv := make([]word, len(c.Args))
	for i, w := range c.Args {
		argv[i] = wordOf(w)
	}
	a.resolve(argv, depth)
}

// resolve normalises argv, unwraps wrappers and records the command.
func (a *analysis) resolve(argv []word, depth int) {
	var forms [][]word
	cur := argv
	xargs := false
	for step := 0; step < 10; step++ {
		if cur[0].dyn || cur[0].glob {
			a.unrecog = append(a.unrecog, "command name not statically known")
			a.add(cmd{forms: append(forms, cur)})
			return
		}
		cur = a.head(cur)
		forms = append(forms, cur)
		name := cur[0].s
		switch {
		case unresolvers[name]:
			a.unrecog = append(a.unrecog, name+" runs code that cannot be analysed")
		case shells[name]:
			a.shell(cur, forms, depth)
			return
		case name == "find":
			a.findExec(cur, depth)
		default:
			if next, ok := a.unwrap(cur); ok {
				xargs = xargs || name == "xargs"
				cur = next
				continue
			}
		}
		break
	}
	switch cur[0].s {
	case "cd", "pushd", "popd":
		a.chdir(cur)
	}
	a.add(cmd{forms: forms, xargs: xargs})
}

func (a *analysis) add(c cmd) {
	c.cwd = a.cwd
	a.cmds = append(a.cmds, c)
}

// head strips quoting artefacts from argv[0]: absolute paths in standard dirs
// collapse to the basename; git global options are removed.
func (a *analysis) head(argv []word) []word {
	out := append([]word(nil), argv...)
	if strings.HasPrefix(out[0].s, "/") && stdDirs[path.Dir(out[0].s)] {
		out[0].s = path.Base(out[0].s)
	}
	switch out[0].s {
	case "git":
		out = a.gitGlobals(out)
	case "rm":
		out = normaliseRm(out)
	}
	return out
}

// normaliseRm maps long options to short ones, drops "--" and cleans absolute
// targets, so `rm --recursive --force /`, `rm -rf -- /` and `rm -rf /*` all
// look like `rm -f -r /`.
func normaliseRm(argv []word) []word {
	out := []word{argv[0]}
	for _, w := range argv[1:] {
		switch {
		case w.dyn:
		case w.s == "--":
			continue
		case w.s == "--recursive":
			w.s = "-r"
		case w.s == "--force":
			w.s = "-f"
		case strings.HasPrefix(w.s, "/"):
			c := path.Clean(w.s)
			if c == "/*" || c == "/." {
				c = "/"
			}
			w.s = c
		}
		out = append(out, w)
	}
	return out
}

var gitValueOpts = map[string]bool{"-C": true, "--git-dir": true, "--work-tree": true, "--namespace": true, "--super-prefix": true, "--config-env": true}

func dangerousGitConfig(kv string) bool {
	k := strings.ToLower(kv)
	if i := strings.IndexByte(k, '='); i >= 0 {
		k = k[:i]
	}
	for _, p := range []string{"alias.", "pager.", "url.", "protocol."} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	for _, s := range []string{".command", ".cmd", ".program", ".helper", ".textconv", ".sshcommand", ".fsmonitor", ".hookspath", ".editor", ".pager", ".askpass", ".external"} {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

func (a *analysis) gitGlobals(argv []word) []word {
	out := []word{argv[0]}
	i := 1
	for i < len(argv) && strings.HasPrefix(argv[i].s, "-") && !argv[i].dyn {
		o := argv[i].s
		switch {
		case o == "-c":
			if i+1 >= len(argv) || argv[i+1].dyn || dangerousGitConfig(argv[i+1].s) {
				a.unrecog = append(a.unrecog, "git -c with alias or command-running config")
			}
			i += 2
		case strings.HasPrefix(o, "--exec-path"):
			a.unrecog = append(a.unrecog, "git --exec-path")
			i++
		case gitValueOpts[o]:
			i += 2
		default:
			i++
		}
	}
	if i > len(argv) {
		i = len(argv)
	}
	return append(out, argv[i:]...)
}

// wrapper describes how to skip options of a command that runs its argument.
type wrapper struct {
	valOpts map[string]bool
	skipPos int  // positionals before the wrapped command (timeout DURATION)
	assigns bool // accepts NAME=value before the command
}

func opts(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

var wrappers = map[string]wrapper{
	"env":     {valOpts: opts("-u", "-C", "--unset", "--chdir"), assigns: true},
	"sudo":    {valOpts: opts("-u", "-g", "-h", "-p", "-C", "-T", "-r", "-t", "-U", "-D"), assigns: true},
	"doas":    {valOpts: opts("-u", "-C")},
	"nohup":   {},
	"nice":    {valOpts: opts("-n")},
	"timeout": {valOpts: opts("-s", "-k", "--signal", "--kill-after"), skipPos: 1},
	"stdbuf":  {valOpts: opts("-i", "-o", "-e")},
	"setsid":  {},
	"ionice":  {valOpts: opts("-c", "-n", "-p", "-P", "-u")},
	"time":    {valOpts: opts("-f", "-o")},
	"xargs":   {valOpts: opts("-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a", "-J")},
	"command": {},
	"builtin": {},
	"exec":    {valOpts: opts("-a")},
	"watch":   {valOpts: opts("-n", "-d")},
	"flock":   {valOpts: opts("-w", "-E"), skipPos: 1},
}

// unwrap returns the command wrapped by argv[0], if argv[0] is a wrapper.
func (a *analysis) unwrap(argv []word) ([]word, bool) {
	name := argv[0].s
	w, ok := wrappers[name]
	if !ok {
		return nil, false
	}
	i := 1
	for i < len(argv) {
		s := argv[i].s
		switch {
		case argv[i].dyn:
			a.unrecog = append(a.unrecog, name+" with dynamic option")
			return nil, false
		case s == "--":
			i++
			goto done
		case strings.HasPrefix(s, "-") && len(s) > 1:
			if query, bad := specialWrapperOpt(name, s); query || bad {
				if bad {
					a.unrecog = append(a.unrecog, name+" "+s+" runs an unparsed command string")
				}
				return nil, false // query form (command -v) or opaque string: nothing to unwrap
			}
			if w.valOpts[s] {
				i += 2
			} else {
				i++
			}
		case w.assigns && strings.Contains(s, "=") && envNameRe.MatchString(s[:strings.IndexByte(s, '=')]):
			if dangerousEnv(s[:strings.IndexByte(s, '=')]) {
				a.unrecog = append(a.unrecog, "assignment to "+s[:strings.IndexByte(s, '=')])
			}
			i++
		default:
			goto done
		}
	}
done:
	i += w.skipPos
	if i >= len(argv) {
		return nil, false
	}
	return argv[i:], true
}

// shell handles `bash -c "<str>"`; a shell that reads its script from stdin is
// unrecognised.
func (a *analysis) shell(argv []word, forms [][]word, depth int) {
	valued := opts("-o", "-O", "+o", "+O", "--rcfile", "--init-file")
	hasC := false
	i := 1
	for i < len(argv) {
		s := argv[i].s
		if argv[i].dyn || (!strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "+")) {
			break
		}
		if !strings.HasPrefix(s, "--") && strings.HasPrefix(s, "-") && strings.Contains(s, "c") {
			hasC = true
			i++
			break
		}
		if valued[s] {
			i++
		}
		i++
	}
	switch {
	case hasC && i < len(argv) && !argv[i].dyn:
		a.add(cmd{forms: forms, passthrough: true})
		a.scoped(func() { a.run(argv[i].s, depth+1) })
	case hasC:
		a.unrecog = append(a.unrecog, "shell -c string not static")
		a.add(cmd{forms: forms, passthrough: true})
	case i >= len(argv):
		a.unrecog = append(a.unrecog, "shell reads its script from stdin")
		a.add(cmd{forms: forms, passthrough: true})
	default:
		a.add(cmd{forms: forms}) // `bash script.sh`: an ordinary command
	}
}

// findExec resolves the commands run by find -exec/-execdir/-ok/-okdir.
func (a *analysis) findExec(argv []word, depth int) {
	for i := 1; i < len(argv); i++ {
		switch argv[i].s {
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(argv) && argv[j].s != ";" && argv[j].s != "+" {
				j++
			}
			if j > i+1 {
				a.resolve(argv[i+1:j], depth)
			}
			i = j
		}
	}
}

// wordOf flattens a shell word. Dynamic parts make the word dyn.
func wordOf(w *syntax.Word) word {
	var out word
	var sb strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			s, glob := unescape(x.Value)
			sb.WriteString(s)
			out.glob = out.glob || glob
			if braceList.MatchString(s) {
				out.dyn = true
			}
		case *syntax.SglQuoted:
			if x.Dollar {
				out.dyn = true
			}
			sb.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				if l, ok := q.(*syntax.Lit); ok {
					s, _ := unescape(l.Value)
					sb.WriteString(s)
				} else {
					out.dyn = true
					sb.WriteString("$_")
				}
			}
		default:
			out.dyn = true
			sb.WriteString("$_")
		}
	}
	out.s = sb.String()
	return out
}

// unescape removes backslashes of an unquoted literal and reports whether it
// holds an unescaped glob character.
func unescape(s string) (string, bool) {
	if !strings.ContainsAny(s, `\*?[`) {
		return s, false
	}
	var sb strings.Builder
	glob := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			if s[i] != '\n' {
				sb.WriteByte(s[i])
			}
		case c == '*' || c == '?' || c == '[':
			glob = true
			sb.WriteByte(c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String(), glob
}

// specialWrapperOpt flags `command -v` (runs nothing) and options that hand the
// wrapper an unparsed command string (env -S, sudo -s/-i/-e).
func specialWrapperOpt(name, opt string) (query, opaque bool) {
	switch name {
	case "command":
		return strings.ContainsAny(opt, "vV"), false
	case "env":
		return false, strings.HasPrefix(opt, "-S")
	case "sudo":
		return false, opt == "-s" || opt == "-i" || opt == "-e"
	}
	return false, false
}
