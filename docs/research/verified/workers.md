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
