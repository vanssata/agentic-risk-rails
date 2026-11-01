# W3-D: MCP, Agent Skills, simplify tools (verified 2026-11-01)

## FACTS
- [V] go-sdk v1.8.0 (module cache, read from source): `mcp.NewServer(*Implementation, *ServerOptions)`, generic `mcp.AddTool[In,Out](s, *Tool, handler)` (infers input/output schema; panics on bad schema), `(*Server).Run(ctx, Transport)`, `&mcp.StdioTransport{}` (newline-delimited JSON on stdin/stdout), `mcp.NewInMemoryTransports()` returns (a, b) for an in-process client/server pair, `mcp.NewClient(impl, opts).Connect(ctx, transport, nil)`.
- [V] SDK latest protocol version constant: `2026-07-28` (also supports 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05) - go-sdk mcp/shared.go.
- [V] Agent Skills spec https://agentskills.io/specification : dir `<name>/SKILL.md`; YAML frontmatter `name` (1-64, [a-z0-9-], no leading/trailing/double hyphen, must equal dir name) and `description` (1-1024) required; optional license, compatibility (<=500), metadata, allowed-tools. Keep SKILL.md < 500 lines.
- [V] Claude Code https://code.claude.com/docs/en/skills : project skills at `.claude/skills/<name>/SKILL.md`; `name` optional (defaults to dir), `description` recommended, truncated at 1536 chars in listing.
- [V] Codex https://learn.chatgpt.com/docs/build-skills : repo skills at `.agents/skills` (cwd up to repo root), user `$HOME/.agents/skills`; frontmatter requires `name`, `description`.
- [V] jscpd (https://github.com/kucherenko/jscpd): `--reporters json` (`-r`), `--output DIR` (`-o`), `--report-name NAME` (default `jscpd-report` -> `<dir>/jscpd-report.json`), `--min-lines/-l`, `--min-tokens/-k`.
- [V] ast-grep https://ast-grep.github.io/reference/cli/scan.html : `ast-grep scan --json=stream|compact|pretty`; binary name `ast-grep` (on Linux `sg` is util-linux, so we never call `sg`).

## READ
go-sdk mcp/{server,transport,shared}.go; agentskills.io/specification; Claude and Codex skills docs; jscpd README; ast-grep scan reference.

## GAPS
- [U] jscpd JSON entry fields: we assume `duplicates[].firstFile.name`, `secondFile.name`, `lines`, `firstFile.start/end` (classic schema; page fetched did not list them). Parser ignores unknown fields.
- [U] ast-grep stream object fields: assume `file`, `ruleId`, `message`, `range.start.line`.
- [U] Gemini CLI / Cursor skill directories not confirmed; skills are rendered only for Claude and Codex.
- jscpd/ast-grep not installed on the dev host; behaviour verified with FakeBin only.

## COST
~12 fetches, no paid calls.

## GAP (accepted, review round 1)
- `affected` is not static: mapping files runs the project's test tooling (jest config, `go list`). Behaviour unchanged by decision; stated in the tool description; to be recorded in errata.
