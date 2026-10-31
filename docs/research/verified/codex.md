# Codex adapter — verified facts

Pinned: **codex-cli 0.166.0** (`codex --version`), Linux, bubblewrap 0.11.1. Date 2026-10-31.
Docs moved: developers.openai.com/codex/* 308-redirects to learn.chatgpt.com/docs/*.
Label: [V] verified (docs read this session and/or observed on the pinned binary — marked `obs`), [U] unverified.

## FACTS

| claim | URL / evidence | mark |
|---|---|---|
| Hooks are read from `~/.codex/hooks.json`, `~/.codex/config.toml`, `<repo>/.codex/hooks.json`, `<repo>/.codex/config.toml`; inline form is `[[hooks.PreToolUse]]` + `[[hooks.PreToolUse.hooks]]`; all matching hooks from all files run (merged, not replaced) | https://learn.chatgpt.com/docs/hooks | [V] |
| Hooks are enabled by default (`features.hooks`, `codex features list` => stable, true) | https://learn.chatgpt.com/docs/hooks ; obs `codex features list` | [V] |
| Project `.codex/` layer (config, hooks, rules) loads **only when the project is trusted** (`projects.<path>.trust_level = "trusted"` in the user config); untrusted project => the whole project layer is skipped | https://learn.chatgpt.com/docs/config-file/config-reference ; obs: `codex sandbox` in an untrusted dir ignored `.codex/config.toml` (stayed read-only default), trusted dir applied it | [V] |
| Non-managed hooks must be reviewed/trusted (hash-bound) before they run; `/hooks` to trust; `--dangerously-bypass-hook-trust` skips for one invocation (exists in `codex exec --help`) | hooks doc ; obs help | [V] |
| Hook handler fields: `type` (`command`\|`mcp_tool`), `command`, `timeout` (seconds, default 600), `statusMessage`, `async`; `matcher` is a regex; `"*"`, `""` or omitted match everything | hooks doc ; obs `matcher="*"` fired | [V] |
| obs: `.codex/hooks.json` must be wrapped `{"hooks":{"PreToolUse":[{matcher,hooks:[…]}]}}`; the bare `{"PreToolUse":[…]}` form was silently ignored (hook did not fire). Hook `command` runs through a shell (`rr … \|\| exit 2` worked: fake rr exit 7 => blocked) and inherits PATH | observed | [V] |
| PreToolUse events: shell (`tool_name` = `Bash`, also unified exec), file edits (`tool_name` = `apply_patch`, matchable as `apply_patch`/`Edit`/`Write`), MCP tools (`mcp__<server>__<tool>`, `tool_input` = arguments), other local function tools. Hosted tools (WebSearch) do **not** trigger it. File reads by native tools are not documented as covered | hooks doc | [V] |
| "Treat tool hooks as a useful guardrail, not a complete enforcement boundary." | hooks doc | [V] |
| PreToolUse stdin keys: `session_id, turn_id, transcript_path, cwd, hook_event_name, model, permission_mode, tool_name, tool_use_id, tool_input` (+ optional `agent_id, agent_type`) | https://raw.githubusercontent.com/openai/codex/main/codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json ; obs below | [V] |
| obs Bash payload: `{"session_id":..,"turn_id":..,"transcript_path":..,"cwd":"/abs/ws","hook_event_name":"PreToolUse","model":"gpt-6.1-sol","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"echo hello > a.txt"},"tool_use_id":"exec-..."}` | observed with `codex exec` + logging hook | [V] |
| obs apply_patch payload: `tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: b.txt\n+hi\n*** End Patch"}`; patch paths are **relative to `cwd`** | observed | [V] |
| MCP payload: `tool_name":"mcp__filesystem__read_file"`, `tool_input` = arguments object (not observed on this binary) | hooks doc | [V] doc-only |
| Output protocol: deny = JSON `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}` (preferred), legacy `{"decision":"block","reason":…}`, or **exit 2 + reason on stderr**. obs: exit 2 + stderr => tool call not executed ("Command blocked by PreToolUse hook: <stderr>"); JSON deny with exit 0 => blocked, file not created | hooks doc ; obs | [V] |
| `permissionDecision: "ask"`, legacy `approve`, `continue:false`, `stopReason`, `suppressOutput` are **unsupported for PreToolUse**: hook run is marked failed and **the tool call continues** | hooks doc | [V] |
| **Failure is fail-OPEN.** obs: hook exiting 1 => "hook: PreToolUse Failed", command ran; hook exceeding `timeout` (sleep 20, timeout 2) => "Failed", command ran. Docs: MCP-hook errors/timeouts do not block | observed (a.txt created in both cases) ; hooks doc | [V] |
| `permission_mode` in hook input was `bypassPermissions` with `--dangerously-bypass-hook-trust`/`approval_policy=never` run | observed | [V] |
| `sandbox_mode` = `read-only`\|`workspace-write`\|`danger-full-access`; `[sandbox_workspace_write]`: `writable_roots`, `network_access`, `exclude_tmpdir_env_var`, `exclude_slash_tmp` — **no per-path read-only/deny key there** | config-reference | [V] |
| `approval_policy` = `on-request`\|`never`\|`{granular=…}`; `untrusted` unsupported, `on-failure` deprecated | config-reference | [V] |
| **Permission profiles** give per-path control: `default_permissions = "<name>"`, `[permissions.<name>.filesystem]` with absolute paths/globs/tokens (`:minimal`, `:workspace_roots`) valued `"read"`\|`"write"`\|`"deny"` (deny = unreadable); `[permissions.<n>.filesystem.":workspace_roots"]` takes paths relative to the workspace root (`"."` = root) | config-reference ; obs | [V] |
| obs (`codex sandbox`, trusted ws, profile `"/"="read"`, `":workspace_roots"."."="write"`, `riskrails.yaml`/`.github/**`="read", `.env*`="deny"): write to riskrails.yaml and .github/w.yml => `Read-only file system` (EROFS); cat .env.local => `Permission denied` (EACCES); other workspace files writable; nonexistent paths/globs in rules are accepted | observed | [V] |
| obs: `.git` is entirely read-only inside the sandbox in both `workspace-write` and the profile (write `.git/config`, create `.git/x`, mkdir `.git/refs/remotes/origin` => EROFS). Adding a rule for a **nonexistent path under `.git`** (e.g. `.git/refs/remotes/**` in a fresh repo) makes bwrap fail: `Can't create file at …/.git/refs/remotes: Read-only file system` — so the adapter emits **no** `.git/**` rules | observed | [V] |
| obs: with a custom profile `/tmp` is **not** writable unless `"/tmp"="write"` is listed (legacy workspace-write includes /tmp) | observed | [V] |
| obs: network is off in `workspace-write` and in the profile (curl: could not resolve host). `[permissions.<n>.network]` domain allow/deny is enforced only when experimental `features.network_proxy` (default false) is on | observed ; config-reference | [V] |
| `[agents]`: `default_subagent_model`, `default_subagent_reasoning_effort`, `max_concurrent_threads_per_session`, `agents.<name>.config_file` (per-role TOML layer; no inline per-agent `model` key documented) | config-reference | [V] |
| `codex sandbox [OPTIONS] <COMMAND>...` runs an arbitrary command under the Linux sandbox using the config (`-c`, cwd project layer); default policy without config is read-only | obs `codex sandbox --help` | [V] |
| `codex exec`: `-s/--sandbox`, `-c key=value`, `--dangerously-bypass-hook-trust`, `--skip-git-repo-check`, `--ignore-user-config`, `--ephemeral`. **No `-a`** on `exec` (only top-level `codex -a`); **`--full-auto` is rejected** ("unexpected argument") | obs help / run | [V] |
| Linux sandbox: bubblewrap; uses first `bwrap` on PATH, otherwise a bundled helper needing unprivileged userns; macOS Seatbelt | https://learn.chatgpt.com/docs/sandboxing | [V] |
| MCP servers inside or outside the sandbox | not stated in docs | [U] |
| Admin `requirements.toml` `allow_managed_hooks_only` exists; managed hooks are trusted by policy | https://developers.openai.com/codex/config-basic (via fetch) | [V] |

## READ
hooks doc, config-reference (first 100k chars + permissions section), sandboxing doc, hook input JSON schema, hook output schema (summary); `codex --help`, `exec --help`, `sandbox --help`, `features list`; live `codex exec` runs (~16k tokens total) and `codex sandbox` runs in temp CODEX_HOME.

## CONFLICTS with DES
1. **DES §3.2 `fail_closed` / ADR-9 "hook crash/timeout = deny"**: Codex hooks fail OPEN (crash, timeout, unsupported output). Mitigation in adapter: hook command is `rr guard … || exit 2` (any non-zero/missing binary => exit 2), and `rr guard` must self-limit below the hook `timeout` (generated `timeout = 10`); a hook killed by Codex's timeout still runs the tool. The OS sandbox, not the hook, is the boundary — consistent with DES §3.4 step 0 but the "fail-closed" claim holds only inside `rr`.
2. **DES §3.4 step 0** said Codex `sandbox_mode`/`[sandbox_workspace_write]` compile `enforcement.sandbox`: those keys cannot express per-path rules. Resolution (no conflict in outcome): use **permission profiles** (`default_permissions` + `[permissions.*.filesystem]`), verified to give read-only and unreadable paths. `.git/**` entries are not emitted (always read-only; nonexistent subpaths break bwrap).
3. **DES §8.2 `codex exec --sandbox workspace-write -a never`**: `exec` has no `-a`; use `-c approval_policy=never` (or config). `--full-auto` is removed (DES said "deprecated [U]").
4. **`ask` (documented limitation, accepted)**: Codex PreToolUse cannot ask (unsupported => tool continues). `Ask` is rendered as a block (exit 2) at every level, so `commands.ask` items (git commit, composer require, …) are hard-blocked under Codex at L0/L1. The stderr reason tells the human what to do: `rr: needs approval — run it yourself: <command> (<reason>)`. Codex's own `approval_policy = "on-request"` does not help because the hook runs before it.
5. DES §4.1 "per-agent `model`": only `agents.<name>.config_file` documented; adapter emits only `[agents]` defaults.

## Profile compilation rules (fix round 1) — observed on 0.166.0 [V]
- Glob paths only support `deny`; `read` needs an **exact path or a trailing `/**`** (`Error: filesystem glob path '**/.mcp.json' only supports deny access`). Nested rules below a read-only dir whose target is absent make bwrap fail (`.github/**` + `.github/workflows/**` with no `workflows/`), so covered entries are dropped.
- Sources: read-only = `core.AlwaysProtected` + `enforcement.protected_paths` + `sandbox.readonly` + `sandbox.no_write`; no-read = `secret_reads` + `sandbox.no_read`. Slash-less deny patterns become `**/<pat>` (any depth, gitignore semantics as internal/globs). Read-only: exact paths stay root-relative; other globs degrade to the literal directory prefix + `/**`; no prefix => dropped. Absolute/`~` read-only entries are skipped (everything outside the workspace except `/tmp` is read-only already). Nothing under `.git/` is emitted: `.git` is read-only in the sandbox anyway and an absent path below it breaks bwrap.

## GAPS
- Read-only protection of slash-less names at depth is not expressible: `riskrails.yaml`/`.mcp.json` are protected at the repo root only (nested copies writable), and glob read-only patterns such as `.env*` without a directory prefix are dropped. Secret reads are covered at any depth (`**/.env*` deny). Residual coverage comes from the PreToolUse hook only (fail-open).
- Directory-level degradation of a glob (`src/*.php` => `src/**`) over-protects.
- Wave-3 item: `rr doctor` check of Codex hook trust (untrusted hooks silently do not run).
- Hook-input for MCP tools only doc-verified, not observed.
- MCP servers inside sandbox: [U] (DES §14.7 stays open).
- Egress allow-list cannot be enforced (network proxy feature experimental): network is fully off; allow-listed hosts (package installs) are unreachable from the agent sandbox.
- `.git` read-only for the agent ⇒ the agent cannot `git commit` inside the sandbox; commits need the host/runner (conflicts with "atomic commit per step" unless the runner commits).
- Native file-read tool coverage by PreToolUse undocumented; `secret_reads` protection relies on the sandbox deny rules.
- Hook trust: a generated `.codex/config.toml` hook needs one-time user trust (`/hooks`) or `--dangerously-bypass-hook-trust`; until trusted the hook does not run (fail-open). `rr doctor` should flag it.
- Project-layer trust: untrusted project ⇒ none of the generated config applies (sandbox then falls back to Codex defaults).
- macOS Seatbelt behaviour of profiles not tested.

## COST
Research ≈ 12 doc/schema fetches + 5 live `codex exec` runs (≈ 2.7k–5.5k tokens each; gpt model via user's auth copied into a temp CODEX_HOME). No writes to the real `~/.codex`.
