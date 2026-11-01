# Degrade adapters (Kiro, Copilot, OpenCode) — verified facts

Date 2026-11-01. [V] = read in the cited docs this session (not observed on a binary); [U] = not confirmed.
`copilot` in /usr/bin is only an installer stub ("GitHub Copilot CLI was not found"); `opencode`, `kiro-cli` not installed. Nothing here was observed on a binary.

## FACTS

| claim | URL | mark |
|---|---|---|
| Copilot: repo hooks live in `.github/hooks/*.json` (`"version": 1`, `hooks` map keyed by event; `preToolUse` entry has `bash`/`powershell`); cloud agent loads them from the cloned repo; CLI combines them with user/policy/plugin hooks | https://docs.github.com/en/copilot/reference/hooks-configuration | [V] |
| Copilot `preToolUse` camelCase input: `sessionId, timestamp, cwd, toolName, toolArgs`; PascalCase `PreToolUse`: `hook_event_name, session_id, timestamp, cwd, tool_name, tool_input` | same | [V] |
| Copilot deny = stdout JSON `{"permissionDecision":"deny","permissionDecisionReason":"…"}`; exit 2 always denies; command hooks fail closed on error; **timeouts fail open**; HTTP hooks fail open; `ask` is treated as deny under the cloud agent | same | [V] |
| Copilot tool names (`bash`, `edit`, …) and the shape of `toolArgs` for file tools | — | [U] |
| OpenCode `opencode.json` `permission`: values `allow`/`ask`/`deny`; keys `read, edit, glob, grep, bash, task, webfetch, websearch, external_directory, doom_loop`; `"*"` is the default; `bash` and `edit` take pattern objects (`*`, `?`); **last matching rule wins** (put `"*"` first); `edit` covers write and patch | https://opencode.ai/docs/permissions/ | [V] |
| OpenCode reads `AGENTS.md` in the project root | https://opencode.ai/docs/rules/ | [V] |
| OpenCode plugins load from `.opencode/plugins/`; `tool.execute.before` throwing is used in an example to block a read, but blocking is not documented as a guarantee | https://opencode.ai/docs/plugins/ | [U] |
| Kiro: project hooks are `.kiro/hooks/<id>.json` (`version: "v1"`, `hooks[]` with `name`, `trigger`, `matcher`, `action.type` command\|agent); PreToolUse "can validate and block tool usage"; input has `hook_event_name, cwd, session_id, tool_name, tool_input` | https://kiro.dev/docs/hooks/ , https://kiro.dev/docs/hooks/types/ | [V] |
| Kiro: which exit code / output blocks a PreToolUse command hook; behaviour on hook failure | hook-actions page not read | [U] |
| Kiro `permissions.yaml` outside the repo (DES §10) | — | [U] |
| `git commit --no-verify` skips pre-commit hooks; so a pre-commit hook is advice, not protection | git docs (well known) | [V] |

## READ
Docs pages above only. Copilot CLI help could not be read (stub).

## GAPS
- Kiro block semantics unknown ⇒ no Kiro hook is generated; Enforcement = `ci_only`.
- OpenCode has native permissions (generated as an extra layer) but no confirmed enforcing hook ⇒ `ci_only`.
- Copilot hook protocol is documented, not observed; tool names/args are [U]. Any payload the adapter does not understand is a deny.

## COST
~8 doc fetches; no model calls.
