# Gemini CLI adapter — verified facts

Read 2026-11-01 from github.com/google-gemini/gemini-cli `main` docs; `package.json` on main showed `0.67.0-nightly.20261020` (docs follow main, not a stable tag). `gemini` is NOT installed here: nothing was observed on a binary, there is no contract test.
Label: [V] read in the docs this session, [U] unverified.

## FACTS

| claim | URL | mark |
|---|---|---|
| Hook events: BeforeTool, AfterTool, BeforeAgent, AfterAgent, BeforeModel, BeforeToolSelection, AfterModel, SessionStart, SessionEnd, Notification, PreCompress | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/reference.md | [V] |
| Common stdin: `session_id, transcript_path, cwd, hook_event_name, timestamp`; BeforeTool adds `tool_name`, `tool_input` (model's raw arguments), optional `mcp_context`, `original_request_name` | same | [V] |
| Deny: stdout JSON `{"decision":"deny"\|"block","reason":"…"}` with exit 0, or exit 2 with the reason on stderr. Exit 0 = success (stdout parsed as JSON); exit 2 = block; any other code = "non-fatal failure, CLI continues with a warning" (fail-open) | same | [V] |
| Hook `timeout` is milliseconds, default 60000 | same | [V] |
| settings.json: `{"hooks":{"BeforeTool":[{"matcher":"<regex>","sequential":bool,"hooks":[{"type":"command","command":…,"name":…,"timeout":ms,"description":…}]}]}}`; `matcher` is a regex for tool events | same | [V] |
| Tool names/args: `run_shell_command{command,description,dir_path,is_background}`; `read_file{file_path,offset,limit}`; `write_file{file_path,content}`; `replace{file_path,instruction,old_string,new_string,allow_multiple}`; `list_directory{dir_path,…}`; `glob{pattern,path,…}`; `grep_search{pattern,path,include}` | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/file-system.md , .../docs/tools/shell.md | [V] |
| **Source (read 2026-11-01):** `glob{pattern,dir_path,case_sensitive,...}` and `grep_search{pattern,dir_path,include_pattern,exclude_pattern,names_only,...}` take the directory in **`dir_path`** (no `path` parameter; the older docs page said `path`, so the adapter reads both). `search_file_content` is a legacy alias of grep. `read_many_files{include[],exclude[],recursive,...}`. Built-in tool names: glob, grep_search, list_directory, read_file, run_shell_command, write_file, replace, google_web_search, write_todos, web_fetch, read_many_files, get_internal_docs, activate_skill, ask_user, exit_plan_mode, enter_plan_mode, update_topic, complete_task, read_mcp_resource, list_mcp_resources | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/core/src/tools/definitions/base-declarations.ts , .../tools/grep.ts , .../tools/glob.ts , .../tools/read-many-files.ts , .../tools/tool-names.ts | [V] |
| Policy TOML: `[[rule]]` with `toolName` (string or array, wildcards), `commandPrefix`, `commandRegex` (not with prefix), `argsPattern` (regex over stable JSON of args), `decision` = allow\|deny\|ask_user, `priority` 0–999 within tier, `denyMessage`, `modes`, `interactive`, `mcpName`, `subagent`; `ask_user` in non-interactive mode is treated as deny | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/policy-engine.md | [V] |
| Final priority = tier base + priority/1000; tiers Default 1, Extension 2, Workspace 3, User 4, Admin 5. The doc's own examples compute with a different numbering (user 3.xxx, admin 4.xxx) | same | [V] (CONTRADICTORY, as DES notes) |
| **Workspace tier (`<repo>/.gemini/policies/*.toml`) is disabled: "policies have no effect" (issue #18186).** User tier `~/.gemini/policies/*.toml`; admin `/etc/gemini-cli/policies` (Linux), `/Library/Application Support/GeminiCli/policies` (macOS) | same | [V] |
| Subagents: `.gemini/agents/*.md` frontmatter `name` (slug), `description`, `kind` (local\|remote), `tools` (array), `mcpServers`, `model` (default `inherit`), `temperature` 0–2, `max_turns` (30), `timeout_mins` (10); enabled by default (`experimental.enableAgents:false` turns off) | https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/core/subagents.md | [V] |

## What the adapter does with it

- Tool allowlist: the names above (plus legacy `search_file_content`) and `mcp_*`; any other tool name is a parse error, so deny. Any string value under an unread key that looks like a path (`/`, `~`, `./`, `../`) is added to Paths. `~` expands to the hook process home.
- Hook command `rr guard --runtime gemini --event BeforeTool || exit 2` (errata #9 lesson: exit codes other than 2 fail open); timeout 10000 ms > rr guard's 2 s deadline. Every non-allow verdict is exit 2 + stderr.
- `ask` is rendered as deny (a BeforeTool hook has no documented ask decision). The generated policy TOML keeps `ask_user` for L<2 and `deny` at L≥2.
- The generated `.gemini/policies/riskrails.toml` has no effect in the workspace tier today; it is useful when copied to the user/admin tier. The hook is the project-level enforcement. Enforcement() = `hook_only`.

## CONFLICT

- The policy TOML is generated into the workspace tier although that tier is disabled [V]; DES §10 already records it. No DES claim is refuted.

## GAPS [U]

- Whether project `.gemini/settings.json` hooks load without a trusted-folder prompt; whether untrusted folders skip them.
- Behaviour of a hook that crashes at exit 1 (docs say warning; not observed, so fail-open is assumed and covered by `|| exit 2`).
- Exact stable-JSON form that `argsPattern` sees (key order/spacing), so the generated `"file_path":"…"` regex is untested.
- Whether `commandRegex` is applied per simple command of a compound command.
- `web_fetch` carries URLs inside free-text `prompt`; the adapter does not extract a URL from it, so egress rules do not see it. `read_many_files.include` globs are not put into Paths.
- Agent Skills support; `model` ID strings accepted by `.gemini/agents` (the generator only writes IDs from `SyncInput.Tiers`).
- Whether `{"decision":"allow"}` on stdout is accepted (docs list deny/block only; exit 0 JSON is parsed).
- No contract test against a real binary.
