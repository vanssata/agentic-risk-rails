# Autonomy runner — verified facts

Pinned: claude 2.1.316, codex-cli 0.166.0, Docker 29.9.2. Date 2026-11-01. [V] verified (doc read or observed), [U] not verified.

## FACTS

| claim | URL / evidence | mark |
|---|---|---|
| `--permission-mode` choices: acceptEdits, auto, bypassPermissions, manual, dontAsk, plan | obs `claude --help` | [V] |
| `auto`: a classifier model reviews shell/network actions; file edits in the workdir and reads skip it; explicit `ask` rules still prompt; broad allow rules (`Bash(*)`, interpreters) are dropped on entering auto | https://code.claude.com/docs/en/permission-modes | [V] |
| `claude -p` with no mode set starts in Manual (v2.1.302+): calls that need approval are denied | same | [V] |
| In `-p` without a permission prompt tool, auto mode just denies on repeated blocks (3 in a row / 20 total) and keeps working | same | [V] |
| `dontAsk` denies every call that would prompt; allow rules and PreToolUse-hook approvals still run | same | [V] |
| `bypassPermissions` skips prompts, deny rules still block; refuses root unless a sandbox is detected; project settings cannot select it (nor `auto`): only flag, user, `--settings` or managed settings | same | [V] |
| `--permission-prompts none` (v2.1.259+): anything that would prompt is denied, the mode still decides the rest | https://code.claude.com/docs/en/headless ; obs help | [V] |
| `claude -p` WITHOUT `--bare` runs project `.claude/settings.json` hooks and `.mcp.json`, with no trust dialog; `--bare` skips hooks/CLAUDE.md/MCP and takes settings only from `--settings` | headless | [V] |
| `--settings <file-or-json>` loads extra settings; `--setting-sources user,project,local` selects sources | obs help | [V] |
| `codex exec`: `-s/--sandbox read-only\|workspace-write\|danger-full-access`, `-c key=value`, `--ephemeral`, `--json`, `-o`, `-C`; no `-a`; `--approve-for-me` routes approvals through auto review (not used) | obs `codex exec --help` ; errata #11 | [V] |
| Codex project `.codex/` hooks/config load only for a trusted project; non-managed hooks need hash-bound trust, otherwise silently do not run; `--dangerously-bypass-hook-trust` exists and must NOT be used by the runner | docs/research/verified/codex.md | [V] |
| Docker `--mount type=bind,src=…,dst=…,readonly` over a `rw` bind of the workdir: writes to riskrails.yaml, a `config` file, a `refs/remotes` dir and a `.gh` dir returned EROFS; other files writable | obs docker run (node:20-alpine) | [V] |
| `--network none`: DNS fails (`bad address`), no egress; `/root/.config` absent unless mounted | obs | [V] |
| Docker `--cap-drop`, `--read-only`, `--pids-limit`, `--security-opt`, `--user`, `--tmpfs` exist | obs `docker run --help` | [V] |
| Claude cloud sessions ignore repo hooks ⇒ `ci_only` | DES §10 | [V] |

## READ
permission-modes and headless pages (code.claude.com, first 100k chars of permission-modes), `claude --help`, `codex exec --help`, `docker run --help`, one local container run (no tokens spent). No model call was made.

## DESIGN CONSEQUENCES
- Runner uses `claude -p --permission-mode dontAsk --permission-prompts none` plus the generated hooks as the primary form (deny-by-default, nothing prompts, `ask` is compiled to deny anyway); `auto` is NOT used because its classifier is not a policy and the mode can only come from flags/user settings. DES §8.2 says `auto`: CONFLICT, see report.
- The runner passes its own `--settings` file from outside the workdir; it never reads project settings for mode.
- Codex: `codex exec --sandbox workspace-write -c approval_policy=never`, no hook-trust bypass.
- Container: `--network none` by default (egress allowlist is the proxy's job, GAP).

## GAPS
- Network: `--network none` (the default of `rr run --network`) cannot reach the runtime API, so a real run is BLOCKED with "no network for the runtime API; provide an egress-restricted docker network". The operator supplies a docker network. An egress proxy with allow = runtime API hosts + `enforcement.egress.allow` is wave 4 / owner; not implemented. [U]
- Token usage: `codex exec` output is not parsed (the ledger parser reads rollout files, a different format; the `exec --json` event shape is not verified). Unknown usage with a policy token budget stops the run (fail-closed), so Codex runs stop after the first task until usage parsing exists.
- Push without credentials: gitx blanks the credential helper; needs `Hosting.Push` (CORE_CHANGE_REQUEST).
- Codex hook trust check (`rr doctor`): trust state storage not read; runner only refuses to pass `--dangerously-bypass-hook-trust`.
- Real `claude -p`/`codex exec` inside the container: not run (needs RR_CONTRACT=1, tokens, image with CLIs).

## COST
No tokens spent.
