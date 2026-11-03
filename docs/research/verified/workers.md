# Workers (wave 5, W5-A)

Pinned: codex-cli 0.166.0, claude 2.1.317. Date 2026-11-03. [V] verified by command/observation, [U] not verified.

## FACTS
| Fact | Source | |
|---|---|---|
| `codex exec [PROMPT]`: prompt omitted or `-` reads instructions from stdin | `codex exec --help` 0.166.0 | [V] |
| `-s/--sandbox read-only\|workspace-write\|danger-full-access` | `codex exec --help` | [V] |
| `--ephemeral`: no session files persisted | `codex exec --help` | [V] |
| `-m/--model`, `--json` (JSONL events on stdout), `--skip-git-repo-check` | `codex exec --help` | [V] |
| No turn-limit flag in `codex exec`: `WorkerSpec.MaxTurns` cannot be enforced for Codex, only the timeout | `codex exec --help` | [V] |
| Event shape: `item.completed` agent_message text, `turn.completed.usage.{input_tokens,cached_input_tokens,output_tokens}`, input includes cached | runner.md, ledger.md; `TestCodexContract` (real run, model gpt-5.6-sol) got STATUS DONE and Output > 0 | [V] |
| `codex exec --json` events do not carry the model name: Usage.Model is the `--model` value | not among the parsed fields | [U] |
| `claude -p --output-format json` result has `usage` and `modelUsage` keyed by actual model ID (`{"claude-haiku-5-5":{"inputTokens","outputTokens","cacheReadInputTokens","cacheCreationInputTokens",...}}`) | `claude -p --output-format json --model haiku` on 2.1.317 | [V] |
| Codex read-only sandbox: a worker told to create a file via shell did not create it | `TestCodexContract` | [V] (one run) |

| Codex reads project `.codex/` (config.toml, hooks.json, rules) for a trusted project and `AGENTS.md` / `AGENTS.override.md` from the cwd; the scope check treats ignored copies of these as steering | runner.md rows 39-43 (`.codex/` layer); `AGENTS.override.md` name from memory | [V] `.codex/`, [U] `AGENTS.override.md` |

## READ
`codex exec --help`; docs/research/verified/runner.md, ledger.md.

## GAPS
- Codex read-only was observed once; the model may simply have refused. The sandbox is the control, not the contract test.
- Whether `RR_SCOPE_FILE` is honoured by Codex hooks is unproven (runner.md: hook trust under Codex is [U]).

## COST
Contract run: a few cents (one claude haiku call, three small gpt-5.6-sol calls).

# WAVE 5 — Claude sandbox on the owner's host (2026-11-03)

## FACTS
- claude 2.1.317 is the latest (`npm view @anthropic-ai/claude-code`: latest/next 2.1.317, stable 2.1.311) | command | [V]
- `sandbox.enabled: true` ⇒ every Bash fails: `apply-seccomp: write /proc/self/setgroups (nested userns is capability-restricted; caller must provide CAP_SYS_ADMIN)`; apply-seccomp (inside bwrap) does unshare(CLONE_NEWUSER) then writes setgroups/uid_map | reproduced + binary strings | [V]
- cause: Ubuntu `/etc/apparmor.d/bwrap-userns-restrict` (package apparmor) stacks every child of /usr/bin/bwrap under `unpriv_bwrap`, which has `audit deny capability,`; the sysctl `apparmor_restrict_unprivileged_userns` (0 here) does not matter | file content + `bwrap … unshare -U -r` ⇒ label `bwrap//&unpriv_bwrap`, uid_map EPERM | [V]
- upstream: https://github.com/anthropics/claude-code/issues/43454 (open; since 2.1.92; audit line `apparmor="DENIED" … profile="unpriv_bwrap" comm="apply-seccomp" capname="sys_admin"`) | GitHub API | [V]
- `sandbox.network.allowAllUnixSockets: true` skips apply-seccomp ⇒ Bash works and filesystem denyWrite still holds on 2.1.317 | reproduced | [V]
- but then sandboxed commands reach any unix socket: `curl --unix-socket /var/run/docker.sock …/version` succeeded (owner is in group docker ⇒ host root); only an explicit denyRead+denyWrite on the socket path blocked it (curl exit 7). The host has many more user-reachable sockets (ssh-agent /run/user/1000/gcr/ssh, D-Bus /run/user/1000/bus, JetBrains IPC under ~/.cache) | reproduced | [V]
- sandbox.filesystem paths in project `.claude/settings.json`: `x` and `./x` are relative to the project and enforced; `/x` is an absolute path (not project-relative, unlike permission rules); via `--settings` a relative path was NOT enforced | reproduced | [V]
- trust: Claude ignores project `permissions.allow` until `projects["<repo path>"].hasTrustDialogAccepted` in `$CLAUDE_CONFIG_DIR/.claude.json`; worktrees inherit the main repo's path | reproduced | [V]

## GAPS
- whether Claude can be pointed at a separately profiled bwrap binary [U]; `sandbox.allowNestedUserNamespaces` (≥2.1.305) untested for this error [U]
- FIX applied by the owner (sudo): in `/etc/apparmor.d/bwrap-userns-restrict` the `audit deny capability,` line of `unpriv_bwrap` commented out AND `/etc/apparmor.d/local/unpriv_bwrap` = `capability sys_admin, capability setuid, capability setgid,` (an AppArmor profile allows only what it lists, so removing the deny alone kept CapEff 0); `apparmor_parser -r`. Then, without allowAllUnixSockets: Bash works, `denyWrite` holds (Read-only file system), `/var/run/docker.sock` unreachable (curl exit 7) | reproduced 2026-11-03 | [V]
- then `rr task research|accept|build|close --runtime claude` on rr-sandbox (guarded): 2 Haiku scouts, Sonnet implementer + two Sonnet review stages PASS, close green | real run | [V]
- the commented deny line is in a package conffile and may come back on an apparmor upgrade; the local/ file survives | [U]

# WAVE 6 — preflight, read-only workers, nested config (2026-11-03, claude 2.1.317, codex-cli 0.166.0)

## FACTS
| Fact | Source | |
|---|---|---|
| Trust is stored in `projects["<abs repo path>"].hasTrustDialogAccepted` of `$CLAUDE_CONFIG_DIR/.claude.json` (`~/.claude.json` when the variable is unset); the file also holds MCP configs and per-project state | this host's file (key names only) + https://code.claude.com/docs/en/settings ("~/.claude.json … per-project state such as trust decisions") | [V] |
| `permissions.allow`, `additionalDirectories` and most `env` of the project file wait for trust; `deny` and `ask` rules apply right away, so a project `Read(...)` deny works even in an untrusted repo | https://code.claude.com/docs/en/settings ("The key waits for trust") | [V] |
| `claude -p` skips the workspace trust dialog; settings files failing validation are silently ignored in -p | `claude --help` 2.1.317 | [V] |
| `--setting-sources user,project,local` selects sources; rr's read-only worker passes `user` only, so the project's `permissions.deny Read(...)` does NOT reach it (by construction, not a model run) | `claude --help`; internal/factory/claude.go | [V] |
| `--disallowedTools` takes permission rules; ClaudeRunner.DenyRead appends rules there for read-only workers | `claude --help`; unit test with a fake binary. That `Read(<pattern>)` matches as in settings.json was not run against a model | [V] flag, [U] matching |
| `.claude/settings.json` is read from the session's primary working directory only; a nested `sub/.claude/settings.json` is not a settings source | https://code.claude.com/docs/en/settings ("reads the shared .claude/settings.json from the session's primary working directory") | [V] |
| Nested skills `<subdir>/.claude/skills/*/SKILL.md` DO load, the first time Claude reads or edits a file in that subdirectory, in sessions started above it | https://code.claude.com/docs/en/skills ("Skills in a .claude/skills/ directory below where you started don't load at startup. They load the first time Claude reads or edits a file in that subdirectory") | [V] |
| Codex loads every `.codex/config.toml` from the project root down to the cwd (closest wins), only for a trusted project; so a `.codex/` in a subdirectory below the cwd does not load | https://learn.chatgpt.com/docs/config-file/config-advanced | [V] |
| Codex hooks/rules/skills from nested subdirectories: not documented | same page | [U] |
| `codex sandbox [-c sandbox_mode=workspace-write] [-C dir] -- cmd` runs a command under the Linux sandbox with no model call. Default (read-only): writes to cwd, /etc, HOME, /tmp all fail "Read-only file system". `sandbox_mode=workspace-write`: write in cwd ok, /tmp ok, /etc and HOME and `$HOME/.cache/...` fail; `TMPDIR` unset | run on this host | [V] |
| Claude's sandbox needs, inside bwrap, a nested user namespace (apply-seccomp). Probe without a model: `bwrap --ro-bind / / --dev /dev --proc /proc --unshare-pid --die-with-parent -- unshare -U -r true` (rc 0 on this fixed host); negative control: `… -- touch <tmp>/x` under `--ro-bind / /` must fail. It approximates apply-seccomp, not the exact binary; the failing case (AppArmor) could not be reproduced on this fixed host | run on this host | [V] positive, [U] it fails on an unfixed host |
| Codex read-only: denying READ of chosen paths is not documented (permission profiles are "beta", page not read) | https://learn.chatgpt.com/docs/config-file/config-advanced | [U] |
| Codex `exclude_tmpdir_env_var` / `exclude_slash_tmp` / `writable_roots` exist under `[sandbox_workspace_write]`; defaults not stated; observed: /tmp writable, TMPDIR unset | same page + run | [V] observed, [U] defaults |

## READ
https://code.claude.com/docs/en/settings, https://code.claude.com/docs/en/skills, https://learn.chatgpt.com/docs/config-file/config-advanced, `claude --help`, `codex sandbox --help`.

## GAPS
- Codex read-only workers cannot be denied specific reads by rr today [U]; they can read secret_reads/no_read.
- Whether Claude checks ancestors of the repo path for trust: Preflight accepts only the exact repo root (strict) [U].
- macOS (seatbelt) has no probe; Preflight skips the Claude sandbox probe off Linux.
- Research cache: a READ *directory* that is git-ignored is not content-hashed (only regular files).
