# Verified research: flow (W4-A)

Date: 2026-11-01. Legend: [V] read in this session, [U] not verified. No web access was used; everything below that concerns an external runtime is [U].

## FACTS

claim | URL | status
---|---|---
Claude Code sets `CLAUDECODE=1` in the shell environment of the Bash tool | none read (from memory) | [U]
Claude Code passes `CLAUDE_PROJECT_DIR` to hook commands (already relied on by `projectRoot`) | see claude-code.md | [V] there
A hook process inherits the environment of the runtime process that started it, so `RR_LEVEL`, `RR_HALT_SOCK`, `RR_POLICY_IN_FORCE` set by `docker run -e` reach `rr guard` | none read | [U] (true for Claude Code and Codex hooks as plain child processes; not verified per runtime)
Codex exposes no equivalent of `CLAUDECODE` to its shell tool | none read | [U]

## READ

- In-repo: DES §2.3, §8.1, §8.4, §16; `internal/autonomy/halt.go` (halt socket protocol: one line per connection, `ok` or `halt <reason>`), `internal/autonomy/docker.go` (env set by the runner).

## DESIGN CONSEQUENCES

- `notAgent()` in `cmd/rr/cmd_task.go` refuses close/accept/review when `CLAUDECODE` or `RR_LEVEL` is non-empty. It is a tripwire for the obvious self-approval, not a boundary: the boundary is the sandbox. Codex shells are not detected (see GAPS).

## GAPS

- `CLAUDECODE` and per-runtime env inheritance need a contract test under `RR_CONTRACT=1`.
- A guard rule that denies an agent's `rr task close|accept|review` Bash command would replace the env heuristic (guard is not W4-A's).
