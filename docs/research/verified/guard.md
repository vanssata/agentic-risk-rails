# Verified research: guard (W1-C)

Date: 2026-10-31. Legend: [V] read in this session (URL fetched, or local module source), [U] not verified.

## FACTS

claim | URL | status
---|---|---
`syntax.NewParser(syntax.Variant(syntax.LangBash))` builds a bash parser; `Parse(r io.Reader, name) (*File, error)` returns `File.Stmts`; the zero `LangVariant` is `LangBash` | https://pkg.go.dev/mvdan.cc/sh/v3/syntax | [V]
`syntax.Walk(node, func(Node) bool)` is depth-first and visits every nested node (CmdSubst, ProcSubst, Subshell, Block, FuncDecl, loops, heredoc bodies); returning false prunes | https://pkg.go.dev/mvdan.cc/sh/v3/syntax | [V]
`CallExpr{Assigns, Args []*Word}` is a simple command; redirections hang on the enclosing `*Stmt` (`Stmt.Redirs`), not on the CallExpr (checked by a scratch test on v3.14.1) | local: mvdan.cc/sh/v3@v3.14.1/syntax/nodes.go | [V]
`Word.Lit()` does not unquote: `\git` stays `\git` (Lit.Value keeps the backslash); `'a b'"c$X"` is SglQuoted+DblQuoted parts; `$'..'` is SglQuoted with `Dollar=true`; `{a,b}` stays a literal (brace expansion is not performed by Parse); `g*t` is a plain Lit | scratch test, v3.14.1 | [V]
Redirects: `Redirect.Op` is RdrOut `>`, AppOut `>>`, RdrIn `<`, DplOut `>&` (`2>&1` has Word "1"), Hdoc `<<`; a heredoc body containing `$(id)` is walked, so `id` appears as a CallExpr | scratch test, v3.14.1 | [V]
Claude Code splits compound commands on `&&`, `||`, `;`, `|`, `|&`, `&`, newlines; deny/ask rules apply when any subcommand matches, including inside subshell, command substitution, `for` bodies | https://code.claude.com/docs/en/permissions | [V]
Claude Code strips these wrappers before matching: `timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`; bare `xargs` only without flags; `env`, `sudo`, `watch`, `setsid`, `ionice`, `flock`, `npx`, `docker exec`, `devbox run` are NOT stripped | https://code.claude.com/docs/en/permissions | [V]
Allow rules do not match past an assignment of an unknown env var; deny/ask rules match past any leading assignment | https://code.claude.com/docs/en/permissions | [V]
"A deny or ask rule ... isn't a security boundary": it does not match the same program by absolute path or inside `sh -c`; argument-constraining patterns (e.g. `curl http://github.com/ *`) miss options before the URL, other protocols, redirects, and variables (`URL=...; curl $URL`) | https://code.claude.com/docs/en/permissions | [V]
`find` with `-exec/-delete/-fprint`, `watch`, `setsid`, `ionice`, `flock` cannot be auto-approved by a prefix rule | https://code.claude.com/docs/en/permissions | [V]
A trailing `&&` with nothing after it makes Claude Code treat the command as unparseable and not split it | https://code.claude.com/docs/en/permissions | [V]
Real-world allowlist bypass root causes: validating only the first token while the shell runs the whole string (`sh -c`); stripping leading `KEY=value` env assignments before validation (git hook env vars); flags that write files (`sort -o`) | https://osv.dev/vulnerability/GHSA-vjv9-7m7j-h833 ; https://osv.dev/vulnerability/CVE-2026-55743 ; search-result summaries, pages not opened | [U]
Claude Code's own permission parser is a tree-sitter AST with an allowlist of node types and "too complex => ask" | (DES §11 cites a leaked source) the public docs say only that trailing-operator commands are "unparseable" | [U]
Shell bypass classes (command substitution `$(..)`/backticks, `eval`, `. file`/`source`, `$IFS`/`${IFS}` word splitting, variables or substitutions as command name, quote splitting `g''it`, `\git`, `/usr/bin/git`, `git -c alias.x='!..'`, `exec`, aliases, brace expansion `{git,push}`, glob in command name `/usr/bin/g?t`, `$'\x67it'`) are standard bash semantics | GNU Bash manual https://www.gnu.org/software/bash/manual/bash.html (not opened) | [U]; each class is covered by a corpus case, so the guard's behaviour on them is tested, not assumed

## READ

- mvdan.cc/sh/v3 syntax package docs (first 100k chars), v3.14.1 source for nodes.go/walk.go; scratch parse test.
- Claude Code permissions page (Compound commands, Wrappers, Exec wrappers, "What a Bash rule doesn't match", argument-constraint warning).
- One web search on allowlist bypasses (summaries only).

## DESIGN CONSEQUENCES

1. Walk every node; each `CallExpr` is a command, wherever it sits. Redirections come from `Stmt.Redirs`.
2. Wrapper set is a superset of Claude's (adds env, sudo, doas, exec, setsid, ionice, find -exec) because Claude's own docs say deny rules are not a boundary.
3. Deny/ask are matched against every unwrapped form (outer wrapper, inner command); allow only against the innermost form.
4. Anything not statically resolvable is "unrecognised": non-literal command name, `eval`, `source`/`.`, `alias`, `trap`, function definitions, `bash` without `-c`, dangerous env assignments, `git -c alias.*`.
5. Absolute-path command names collapse to the basename only for standard system dirs; `/tmp/x/git` stays distinct.
6. Egress and path checks are tripwires (DES §14.7): `curl $URL`, `python -c`, test code, git hooks all escape them. The OS sandbox is the boundary.

## GAPS

- Git aliases defined in `.git/config` (`git p` => push --force) are invisible to the guard; defence is `.git/config` read-only in the sandbox.
- `git push origin +main` (force refspec), `git push -f` beyond the one built-in `--force*` => `-f` equivalence.
- Allowed commands execute agent-written code (phpunit, composer scripts); not detectable statically (DES §3.4).
- Case-insensitive filesystems: path globs are case-sensitive.
- Whether Claude Code's real parser is tree-sitter-based remains [U].

## COST

Research: ~3 web calls plus local source reads, well under the 25% budget.
