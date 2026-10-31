# Research: plan + factory (W2-F)

## FACTS
claim | URL | [V]/[U]
--- | --- | ---
Subagent frontmatter `isolation: worktree` runs the subagent in a temporary git worktree branched by default from the DEFAULT branch, not the parent HEAD; auto-cleaned if no changes | https://code.claude.com/docs/en/sub-agents | [V]
Concurrent subagent limit is 20 by default (`Concurrent subagent limit reached`); env `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS` changes it | https://code.claude.com/docs/en/sub-agents | [V]
Nesting: a subagent may spawn subagents up to three layers below the main conversation; env `CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH` (1 = off) | https://code.claude.com/docs/en/sub-agents | [V] (DES "<=20, depth 3" confirmed)
Subagent frontmatter `maxTurns`: at the limit output is returned marked partial | https://code.claude.com/docs/en/sub-agents | [V]
`claude -p` flags: `--output-format text|json|stream-json`, `--max-turns N` (print only; exits with an error at the limit; no default limit), `--model <alias|id>`, `--permission-mode default|acceptEdits|plan|auto|dontAsk|bypassPermissions`, `--max-budget-usd`, `--no-session-persistence`, `-w/--worktree [name]` | https://code.claude.com/docs/en/cli-reference | [V]
`--max-turns` is documented but NOT listed by `claude --help` of 2.1.316 (hidden flag) | `claude --help` (local, 2.1.316) | [V] observed
Field names of the `--output-format json` result object (`result`, `is_error`, `num_turns`, `usage.{input,output,cache_*}_tokens`) | not fetched; from memory | [U] - parser is tolerant, missing usage => 0 tokens; a contract test (RR_CONTRACT=1) must pin it
Codex `agents.max_concurrent_threads_per_session`: max concurrently open spawned-agent threads excluding primary; no numeric default listed (Codex picks) | https://learn.chatgpt.com/docs/config-file/config-reference | [V]
Superpowers implementer prompt: report written to a report file; final message <15 lines with status, commits, test summary, concerns, report path. Statuses: DONE_WITH_CONCERNS = completed with doubts; BLOCKED = cannot complete; NEEDS_CONTEXT = missing info; DONE is not defined on that page | https://github.com/obra/superpowers/blob/main/skills/subagent-driven-development/implementer-prompt.md | [V]

## READ
sub-agents (first 100k chars), cli-reference (flag table), Codex config-reference (first 100k chars; `agents.max_depth` not seen), Superpowers implementer-prompt.md. Local: `claude --help`.

## DECISIONS
- Worker = `claude -p` run by rr with cwd = the step's own git worktree (not the in-session `isolation: worktree`, which branches from the default branch and cannot be controlled by rr).
- Superpowers brief-in / report-out; rr reads the report from stdout JSON (`result`), no report file; status is the `STATUS:` line, absent/unknown => BLOCKED (fail-closed).
- The worker never commits (errata #14/#16/#17): rr commits in the step worktree via the hardened git invocation, then cherry-picks into the integration checkout.

## GAPS
- JSON result field names ([U] above); stream-json not used. Codex `max_depth` unread. Gemini limits not read (not needed by this module).
- Hardened-git helper is unexported in internal/policy (`gitOut`); factory carries a copy (see CORE_CHANGE_REQUESTS).

## COST
4 page fetches, 1 local --help.
