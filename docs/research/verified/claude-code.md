# Claude Code runtime facts (W1-D)

Pinned: **claude 2.1.316** (`claude --version`). Verified 2026-10-31.
Marks: [V] = read in official docs or observed against the installed binary; [U] = unverified.
Docs base: https://code.claude.com/docs/en/ (llms.txt index at /docs/llms.txt).

## FACTS

| claim | URL | |
|---|---|---|
| PreToolUse stdin is JSON with common fields `session_id, prompt_id, transcript_path, cwd, permission_mode, effort, hook_event_name` plus `tool_name, tool_input, tool_use_id` | /hooks | [V] |
| Observed on 2.1.316 (contract test): PreToolUse input has `session_id, transcript_path, cwd, prompt_id, permission_mode, effort{level}, hook_event_name, tool_name, tool_input, tool_use_id` | binary | [V] |
| `Bash` tool_input: `command, description?, timeout? (ms), run_in_background?` | /hooks | [V] |
| `Write`: `file_path, content`; `Edit`: `file_path, old_string, new_string, replace_all?`; `Read`: `file_path, offset?, limit?` | /hooks | [V] |
| `file_path` for Write/Edit/Read is always absolute (`~` and relative expanded before hooks run) | /hooks "File paths" | [V] |
| `Glob`: `pattern, path?`; `Grep`: `pattern, path?, glob?, output_mode?, -i, multiline`; path defaults to cwd | /hooks | [V] |
| `WebFetch`: `url, prompt, offset?`; `WebSearch`: `query, allowed_domains?, blocked_domains?, mode?` (no url) | /hooks | [V] |
| `Agent`: `prompt, description, subagent_type, model?` (alias such as `sonnet`). Observed on 2.1.316: tool_name is `Agent`, tool_input carries `"model":"sonnet"` when the model passes it (closes DES §4.5c [U]) | /hooks; binary | [V] |
| The Agent per-call `model` accepts only an alias (`sonnet|opus|haiku|fable`), never a full ID or `inherit` | /sub-agents | [V] |
| MCP tools are named `mcp__<server>__<tool>`; tool_input is the server's own schema; input also carries `mcp_server{name,source}` (v2.1.274+) | /hooks | [V] |
| `MultiEdit` is "legacy"; its tool_input shape (`file_path, edits[{old_string,new_string,replace_all?}]`) is assumed from the old tool | /permissions | [U] |
| `NotebookEdit` tool_input uses `notebook_path` (named in the permission docs; other fields not listed) | /permissions | [V] path field only |
| Output: stdout JSON `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow|deny|ask|defer","permissionDecisionReason":"..."}}` | /hooks | [V] |
| Exit 2 blocks the call and stderr is the reason; "Exit 2 blocks even when your hook prints JSON", even `allow` JSON does not let it through. **Exit 2 wins.** | /hooks | [V] |
| Exit 0 with no output = no decision, normal permission flow continues (silence is not approval) | /hooks | [V] |
| Other exit codes without valid JSON are a non-blocking error: the action goes ahead | /hooks | [V] |
| Hook `timeout` is in seconds; default 600 for `command` hooks | /hooks | [V] |
| A timed-out / crashed command hook does NOT block by default; `"onFailure": "block"` (v2.1.295+, default `continue`) makes can't-start, exit not in {0,2}, timeout and invalid output block a PreToolUse call. **DES claim "`onFailure: block`, 600 s default" is confirmed; fail-closed needs the explicit setting.** | /hooks | [V] |
| Hook config shape: `hooks.PreToolUse[{matcher, hooks:[{type:"command", command, timeout, onFailure}]}]`; matcher `"*"`/`""`/omitted matches all | /hooks | [V] |
| A PreToolUse `allow` does not bypass deny/ask permission rules; a hook block (exit 2) beats allow rules | /permissions "Precedence among rules, hooks" | [V] |
| Permission rules: `allow`, `ask`, `deny`; deny > ask > allow; a deny rule cannot be carved out by a narrower allow | /permissions | [V] |
| Bash rule syntax: `Bash(npm run build)` exact; `Bash(ls *)` word-boundary prefix (also matches bare `ls`); `Bash(ls*)` plain prefix; `:*` suffix equivalent to trailing ` *`; compound commands: every subcommand must match to be allowed, deny/ask match if any subcommand matches; wrappers (`timeout`, `nice`, `xargs` w/o flags...) stripped | /permissions | [V] |
| Read/Edit path rules use gitignore syntax: `//abs/path`, `~/path`, `/path` = relative to the settings source (project root in `.claude/settings.json`), `path`/`./path` = relative to cwd | /permissions | [V] |
| `Edit(...)` rules cover all built-in editing tools; `Write(path)`, `NotebookEdit(path)`, `MultiEdit(path)`, `Glob(path)` path rules are accepted but **never match** - use `Edit(...)`/`Read(...)`. A `Read` deny also blocks Edit/Write on that path | /permissions | [V] |
| Read/Edit deny rules also apply to Bash file commands Claude recognises (`cat`, `sed`, `tee`, redirections) but not to arbitrary subprocesses | /permissions | [V] |
| `WebFetch(domain:example.com)`, `domain:*.example.com` | /permissions | [V] |
| Sandbox settings: `sandbox.enabled` (off by default), `sandbox.failIfUnavailable` (default: runs unsandboxed), `sandbox.allowUnsandboxedCommands`, `sandbox.excludedCommands`, `sandbox.filesystem.{allowWrite,denyWrite,denyRead,allowRead}`, `sandbox.network.{allowedDomains,deniedDomains,strictAllowlist}` | /sandboxing; /settings-reference | [V] |
| Sandbox scope: **Bash/PowerShell/Monitor commands and children only**. "Claude's file tools, MCP servers, and hooks run outside it"; Read/Edit/Write/WebFetch follow permission rules | /sandboxing, /permissions | [V] |
| Linux needs `bubblewrap` and `socat`; macOS uses Seatbelt; native Windows is unsandboxed | /sandboxing | [V] |
| Sandbox filesystem paths: `/abs`, `~/x` (home), relative resolves against the project root in `.claude/settings.json` (`~/.claude` in user settings). Differs from Read/Edit rule syntax (`//abs`, `/proj`) | /sandboxing | [V] |
| Permission-rule paths and sandbox settings are merged into the final sandbox config | /sandboxing | [V] |
| Glob support (`**`, `*`) inside sandbox.filesystem paths: wildcard deny examples exist (`~/**/.env`); full syntax in "Sandbox path prefixes" not read | /sandboxing | [U] |
| Subagent file `.claude/agents/<name>.md`: frontmatter `name`, `description` (required); `tools`, `disallowedTools`, `model`, `effort` (`low..max`), `maxTurns`, `permissionMode`, ... Unknown fields silently ignored | /sub-agents | [V] |
| `model:` takes `sonnet|opus|haiku|fable`, a full model ID, or `inherit`; omitted => subagent model order (per-call model, frontmatter, `CLAUDE_CODE_SUBAGENT_MODEL`, session model) | /sub-agents | [V] |
| Blocked alias (org `availableModels`): family alias -> newest allowed version of the family; other blocked value -> inherit session model, warning shown in interactive sessions. Plan-level absence of a model is still undocumented | /sub-agents | [V] / [U] plan case |
| `--settings <json-or-file>` sits above project/user files, below managed. `CLAUDE_CONFIG_DIR` relocates user config | /settings | [V] |
| Project `permissions.allow` waits for workspace trust; `deny`/`ask` apply immediately | /settings | [V] |
| Contract (2.1.316, `RR_CONTRACT=1`): project `.claude/settings.json` hook `rr guard ...` with `onFailure: block`, fake `rr` exiting 2 => Write of `hello.txt` blocked, file absent, hook got the JSON above | binary | [V] |
| There is **no documented CLI to run an arbitrary command under Claude Code's sandbox**. Options named: start a session with `--settings`/`/sandbox`, or the separate `@anthropic-ai/sandbox-runtime` package | /sandboxing | [V] |

## READ
- /hooks (first 200k chars: input fields, output protocol, timeouts, onFailure, tool_input tables), /settings, /sandboxing (first 100k), /permissions (rule syntax, precedence, sandbox interplay), /sub-agents (frontmatter, model order, blocked aliases).
- Binary: `claude --version`, `--help`; real runs in temp repo with temp `CLAUDE_CONFIG_DIR` (credentials copied from the caller's config dir, never written back).

## CONFLICTS (with DES)
1. DES §10/ADR-9 write "timeout 600 s default, `onFailure: block`" as if both were defaults. Verified: default timeout 600 s is right, but `onFailure` **defaults to `continue`**; fail-closed requires `onFailure: "block"` (v2.1.295+) and a short explicit `timeout`. The generator sets `timeout: 10`, `onFailure: "block"`.
2. DES §3.4 step 0 implies the sandbox protects `riskrails.yaml` against the agent's tools. Verified: the sandbox covers **Bash only**; Edit/Write/Read are guarded by permission rules and the hook, so the generator also emits `Edit`/`Read` deny rules. Policy path globs are compiled to `Edit(/glob)` (project-anchored).
3. The Agent per-call `model` is an alias (`sonnet`), while `models.by_runtime` may hold full IDs. The guard's "explicit model outside Tiers.Models => deny" must compare against aliases as well (guard/resolver follow-up).

## GAPS
- **EACCES under Claude's sandbox not exercised.** On this host the real sandbox fails to start inside the agent session (`apply-seccomp: write /proc/self/setgroups ... nested userns is capability-restricted`), and fails closed (the command does not run). `TestContractSandboxBlocksPolicyWrite` skips on that error rather than faking a pass. Run it on a host with working user namespaces (Gate 1). A bwrap-only test would test bwrap, not our generated settings, so none was written.
- Glob semantics (`**`) in `sandbox.filesystem.denyRead/denyWrite` and files-vs-directories behaviour: [U]; the generator passes the policy globs through unchanged.
- `MultiEdit` input shape [U]; the parser handles the `edits[]` form.
- Egress (`enforcement.egress`) is not compiled to `sandbox.network` / `WebFetch` rules in this wave; the hook (guard) enforces it.
- Cloud sessions ignore repo hooks (DES §10 [V] claim, not re-verified here).
- Effect of a plan-level missing model on a subagent `model:` is undocumented; generators therefore only emit PASS models.

## COST
Phase R: 8 doc fetches. Contract runs on `--model haiku`, `--max-turns 2`: about 0.005 USD per run, ~4 runs total.
