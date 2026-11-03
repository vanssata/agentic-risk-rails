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
