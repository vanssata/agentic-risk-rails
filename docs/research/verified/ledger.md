# Research: ledger (W2-D)

Structure only was read from local transcripts (keys and types via jq); no content was copied.

## FACTS
claim | source | [V]/[U]
--- | --- | ---
Claude session file is JSONL, one record per line; `type` values include assistant, user, system, attachment, api-request, ai-title, ... Only `type=="assistant"` carries usage | local ~/.claude*/projects/<proj>/<session>.jsonl | [V]
Assistant usage path: `.message.usage.{input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens}` (numbers); also `cache_creation.{ephemeral_1h_input_tokens, ephemeral_5m_input_tokens}`, `iterations[]`, `service_tier`, `speed` | local transcripts | [V]
`input_tokens` excludes cache tokens (cache read/write are separate fields) | local: input_tokens=2 beside cache_read=28889 | [V]
One API message is written several times while streaming (same `message.id`, same `requestId`; 1-8 records per id). In the sample all duplicates carried identical usage; dedupe by `message.id`, last wins | local transcripts | [V]
Records with `message.model == "<synthetic>"` exist (client-generated, zero usage) and must be skipped | local | [U] (key present in code path; sample had none, so skipping is defensive)
Subagent (sidechain) usage is in separate files `<session>/subagents/agent-<id>.jsonl` next to `<session>.jsonl`, with `isSidechain:true`, `agentId`, and the PARENT `sessionId`. Main file has `isSidechain:false` only. Sibling `agent-<id>.meta.json` holds agentType/model/worktree info | local | [V]
Subagent files use their own model (sample: parent claude-opus-5-5, subagent claude-sonnet-5-5), so per-record `message.model` must be used | local | [V]
Observed `cache_creation` was all 1h (`ephemeral_1h_input_tokens`), 5m=0 | local | [V]
Codex rollout: `~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl`; line = {timestamp, ordinal?, type, payload}. Types: session_meta, turn_context, token_usage_record, event_msg(token_count, ...), response_item, ... | local | [V]
Codex `session_meta.payload.id` is the session id; `source` is a string ("vscode"/"exec") or object `{subagent:{thread_spawn:{parent_thread_id}}}` for spawned subagents (each its own file) | local | [V]
Codex model is in `turn_context.payload.model` (not in the usage line) | local | [V]
Codex `token_usage_record.payload.usage` = per-response delta `{input_tokens, cached_input_tokens, cache_write_input_tokens, output_tokens, reasoning_output_tokens, total_tokens}`; also `turn_token_usage` and `thread_token_usage` (cumulative). `event_msg/token_count` repeats the same numbers (`last_token_usage`, cumulative `total_token_usage`) - one record per response; 0 duplicate response_id over 438 records | local | [V]
Codex `input_tokens` INCLUDES cached (total_tokens = input + output; cached <= input in all 438 records) | local | [V]
Claude Fable 5.1 / Opus 5.5 / Sonnet 5.5 / Haiku 5.5 prices (USD/MTok): see COST | https://platform.claude.com/docs/en/about-claude/pricing | [V]
Cache hit = 0.025x base for Fable 5.1, 0.05x for Opus 5.5 and Sonnet 5.5; 5m write 1.25x, 1h write 2x | same | [V]
gpt-6.1-sol: $2.00 input, $0.10 cached input, $10.00 output per MTok (<=272K input); long-context higher | https://developers.openai.com/api/docs/pricing (platform.openai.com/docs/pricing 301s here) | [V]

## READ
~/.claude*/projects/<proj> (one session + its subagents dir, keys only); ~/.codex/sessions/<yyyy>/<mm>/* (keys only); the two pricing pages above.

## GAPS
- `cache_write_input_tokens` in Codex was 0 in every sampled record: whether it is a subset of `input_tokens` is unproven. The parser assumes subset (same as cached); OpenAI publishes no write price, so it is priced at the input rate. [U]
- Claude `core.Usage` has one CacheWrite field; the table prices it at the 1h rate (all samples were 1h). 5m writes would be overpriced by 60%. Needs a core change to split (see report).
- Haiku 5.5 doubles all prices for prompts over 100K tokens; gpt-* are higher over 272K. Not modelled (needs per-request prompt size; Usage has it as input+cache sum).
- Fast mode / batch / priority multipliers not modelled (transcripts have `speed`, `service_tier` but Usage drops them).
- One of the .claude*/projects dirs was not present; layout assumed identical to the other .claude* dir.
- Task-to-session link: no existing event carries it; ledger registers `ledger_session` (runtime, session, phase, path). Nothing writes it yet (hook/runner owner must).

## COST
tokens=n/a calls=3 (2 page fetches + local jq)

### Prices used (prices.json, USD per MTok)
model | input | cache write (1h) | cache read | output
--- | --- | --- | --- | ---
claude-fable-5-1 | 10 | 20 | 0.25 | 50
claude-opus-5-5 | 4 | 8 | 0.20 | 20
claude-sonnet-5-5 | 2 | 4 | 0.10 | 10
claude-haiku-5-5 (<=100K prompt) | 0.10 | 0.20 | 0.01 | 0.50
gpt-6.1-sol | 2 | 2 (assumed) | 0.10 | 10

## CONFLICT
- DES §7.1 said Sonnet 5.5 cache read 0.05x and "output [U] about 5x input": confirmed for Sonnet/Opus 5.5 (output = 5x input: 10/2, 20/4). Haiku 5.5 output is also 5x (0.5/0.1). No conflict; the [U] is now [V]. Note DES lists Haiku/Sonnet/Opus input as $0.10/$2/$4 - matches.

# WAVE 5

## FACTS
- prices.json covers claude-fable-5-1, claude-opus-5-5, claude-sonnet-5-5, claude-haiku-5-5 and gpt-6.1-sol (prices verified above). The runner model IDs of the claude-*-5-5 family match these keys exactly. | local prices.json | [V]
- A model id not in prices.json is never priced as free: `Prices.Cost` returns ok=false and `Group` counts it in `Unpriced` (TestUnpricedModel). | local code | [V]
- Worker runs with unknown usage are put in model bucket `unknown`, which is unpriced and shown as "unpriced or unknown: total incomplete". | local code | [V]
- rr-started workers run with `--no-session-persistence` (Claude) / ephemeral (Codex), so they have no transcript and worker_usage cannot double count ledger_session. | wave 5 plan, not re-checked against the CLIs here | [U]

## GAPS
- The local Codex config (~/.codex/config.toml) sets model "gpt-5.6-sol", which is NOT in prices.json (only gpt-6.1-sol). Its runs show as unpriced, not free. Its price is unverified [U], so it was not added; the owner should verify and add it.

## COST
tokens=n/a calls=0

# WAVE 5 — OpenAI prices (2026-11-03)

## FACTS
- Standard tier, short context (≤272K input), USD/1M — columns Input | Output | Cached input | 30m write | 12h write | https://developers.openai.com/api/docs/pricing (raw HTML fetched 2026-11-03) | [V]
  - gpt-6-astra $10.00 $50.00 $1.00 $12.50 $25.00
  - gpt-6.1-sol $2.00 $10.00 $0.10 $2.50 $5.00 (cache_write was 2 in prices.json: corrected to 2.5)
  - gpt-6-luna $0.10 $0.50 $0.01 $0.125 $0.25
  - gpt-5.6-sol $4.00 $20.00 $0.40 $5.00 $10.00
- Long context (>272K input) costs more (e.g. gpt-6-astra 20 / 2 / 75); Batch and Flex are half of Standard; Priority ("Fast") is 2x; regional processing +10% for models released on or after 2026-03-05 | same URL (agent summary) | [U]

## GAPS
- That the Codex CLI on a subscription login is billed at these API prices is [U]: no Codex-specific price page was found. The ledger shows API-equivalent cost.
- Long-context, batch/flex and priority rates are not modelled; Codex usage carries no cache-write split, so cache_write is not applied to Codex items.
