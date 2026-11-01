# Cursor adapter — verified facts

Read 2026-11-01 from https://cursor.com/docs/agent/hooks and https://cursor.com/docs/agent/third-party-hooks (docs have no version number; pinned by date). `cursor-agent` is NOT installed: nothing observed on a binary, no contract test.
Label: [V] read in the docs this session, [U] unverified.

## FACTS

| claim | URL | mark |
|---|---|---|
| `hooks.json`: `{"version":1,"hooks":{"<event>":[{"command":…,"type":"command"\|"prompt","timeout":seconds,"matcher":regex,"failClosed":bool,"loop_limit":…}]}}`; `matcher` `""`/`"*"` matches everything | https://cursor.com/docs/agent/hooks | [V] |
| Locations: project `<root>/.cursor/hooks.json` (runs from project root), user `~/.cursor/hooks.json`, team (dashboard), enterprise `/etc/cursor/hooks.json` (Linux) | same | [V] |
| 21 events: sessionStart, sessionEnd, preToolUse, postToolUse, postToolUseFailure, subagentStart, subagentStop, beforeShellExecution, afterShellExecution, beforeMCPExecution, afterMCPExecution, beforeReadFile, afterFileEdit, beforeSubmitPrompt, preCompact, stop, afterAgentResponse, afterAgentThought, beforeTabFileRead, afterTabFileEdit, workspaceOpen | same | [V] |
| Common stdin: `conversation_id, generation_id, hook_event_name, workspace_roots, transcript_path` | same | [V] |
| preToolUse in: `tool_name, tool_input, tool_use_id, cwd`; tool_name values `Shell, Read, Write, Grep, Delete, Task, MCP:<tool>`; only the Shell shape `{command, working_directory}` is documented | same + .../third-party-hooks | [V] |
| beforeShellExecution in: `command, cwd, sandbox`; beforeReadFile in: `file_path, content, attachments`; beforeMCPExecution in: `tool_name, tool_input, mcp_server_name`, `url`/`command`; subagentStart in: `subagent_id, subagent_type, task, subagent_model, …` | same | [V] |
| Out: `{"permission":"allow"\|"deny"\|"ask","user_message":…,"agent_message":…}`. `ask` is enforced in beforeShellExecution/beforeMCPExecution, **not in preToolUse**, treated as deny in subagentStart. deny > ask > allow across sources | same | [V] |
| Exit 0 = use JSON; exit 2 = deny. Other non-zero, crash, timeout = **fail open** unless `failClosed:true`. Permission hooks (beforeShell/MCP/ReadFile, subagentStart, preToolUse) block on invalid JSON/schema mismatch even without failClosed | same | [V] |
| Cloud agents: project/team/enterprise hooks only (user hooks do not run); no sessionStart/End, beforeMCPExecution, Tab hooks; command hooks only | same | [V] |
| Cursor can load third-party (Claude Code) hooks; the exact opt-in setting name is not on the pages read | https://cursor.com/docs/agent/third-party-hooks | [V] exists / [U] name |

## What the adapter does with it

- hooks.json registers preToolUse (`*`), beforeShellExecution, beforeReadFile, beforeMCPExecution, subagentStart, each `failClosed:true`, command `rr guard --runtime cursor --event <e> || exit 2`, timeout 10 s.
- Ask is a deny on every event: preToolUse also sees the same shell/MCP calls and deny beats ask, so an ask could never surface. Deny = JSON `permission:"deny"` + stderr + exit 2. Enforcement() = `hook_only`.

## CONFLICT

- None. Note: `ask` works natively in beforeShellExecution/beforeMCPExecution but is deliberately not used (see above).

## GAPS [U]

- `tool_input` shapes of Write/Read/Delete/Grep/Task in preToolUse. The adapter accepts `file_path`|`path` and `contents`|`content` for Write; a Write without full contents is a parse error, hence deny. If Cursor edits files through another tool name (partial edits), that name is unknown to the adapter: deny (fail-closed, but it would block the agent's edits).
- Default `timeout` (documented only as "platform default").
- Whether `tool_input` of beforeMCPExecution is an object or a JSON string (both handled).
- Name of the opt-in setting for third-party hooks; Claude-style hook loading was not used.
- Headless `cursor-agent` hook behaviour; whether `workspace_roots`/`cwd` are always present.
- Whether relative paths in file_path are relative to `cwd` or `workspace_roots[0]`.
- Cursor has no native per-path/command policy file in the docs read (CLI permissions config `.cursor/cli.json` not read): command and path rules live only in the hook.
- No contract test against a real binary.
