# Model availability facts (W2-B)

Verified 2026-11-01. Marks: [V] = read in official docs or observed on the installed binary (claude 2.1.316); [U] = unverified.

## FACTS

- Anthropic `GET /v1/models` returns `data[]{id, display_name, lifecycle active|deprecated|retired, line haiku|sonnet|opus|fable|mythos, capabilities, max_input_tokens, max_tokens, created_at, deprecated_at, retires_at}`, `first_id`, `last_id`, `has_more`; query `limit` (1-1000, default 20), `after_id`, `before_id`, `lifecycle[]`; "retired: inference requests naming it fail" | https://platform.claude.com/docs/en/api/models/list | [V]
- The doc says the list "can be used to determine which models are available for use in the API" but does not say it is filtered per key/plan; `deprecated` = "callable for organizations with existing access, closed to new adopters" (access differs per org) | same | [V] text, filtering itself [U]
- Anthropic errors: 400 `invalid_request_error` (also other 4xx), 401 `authentication_error`, 402 `billing_error`, 403 `permission_error`, 404 `not_found_error`, 413 `request_too_large`, 429 `rate_limit_error`, 500 `api_error`, 504 `timeout_error`, 529 `overloaded_error`. Body: `{"type":"error","error":{"type":...,"message":...},"request_id":...}` | https://platform.claude.com/docs/en/api/errors | [V]
- 429 can also be a monthly spend cap with no `retry-after` (keeps failing); 400 is also returned at a workspace spend limit | same | [V]
- Anthropic request headers in the errors page examples: `x-api-key`, `anthropic-version: 2023-06-01`, `content-type: application/json`; the models page example uses `Authorization: Bearer` | same + list page | [V]
- OpenAI `GET /v1/models`: `{object:"list", data:[{id, created, object:"model", owned_by, shutdown_date?}]}`; "Lists the currently available models"; the page does not say whether it depends on caller access and documents no error shape | https://developers.openai.com/api/reference/resources/models/methods/list | [V] shape, filtering [U]
- OpenAI chat-completions error body (`error.type`, `error.code` such as `model_not_found`) and the `max_completion_tokens` parameter name are NOT confirmed from a fetched page (the OpenAI reference returned 403 to the fetcher) | - | [U]
- OpenRouter `GET https://openrouter.ai/api/v1/models`: bearer token; `{data:[{id:"openai/gpt-4",...}], total_count, links}`; error `{"error":{"code":401,"message":...,"metadata":null}}` (code is an integer HTTP status); documented statuses 400,401,403,404,408,409,429,500,503 | https://openrouter.ai/docs/api/api-reference/models/get-models | [V]
- `count_tokens` "is free to use but subject to requests per minute rate limits"; separate limits from message creation. Whether it validates access to the model is not stated. Not used as a probe | https://platform.claude.com/docs/en/build-with-claude/token-counting | [V] free, validation [U]
- Claude Code with an unknown or unavailable `--model`: exits 1 and prints `There's an issue with the selected model (<id>). It may not exist or you may not have access to it. Run --model to pick a different model.` (plus a `Claude Code doesn't recognize the model ...` line for unrecognised ids). Costs no tokens for a nonexistent id | observed `claude -p ok --model claude-nonexistent-9 --max-turns 1`, 2.1.316 | [V]
- Wording for a model restricted by an org allowlist ("restricted by your organization") and behaviour when the plan (not the org) lacks the model | DES §4.1 | [U] (not reproduced: no restricted account)
- Codex CLI model availability probe | - | [U]

## READ
- https://platform.claude.com/docs/en/api/errors
- https://platform.claude.com/docs/en/api/models/list
- https://platform.claude.com/docs/en/build-with-claude/token-counting
- https://developers.openai.com/api/reference/resources/models/methods/list
- https://openrouter.ai/docs/api/api-reference/models/get-models
- `claude` 2.1.316, one live call

## DECISIONS
- Probe = one `max_tokens:1` completion per candidate; classify on `error.type` (Anthropic) or `error.code`/status (OpenAI, OpenRouter). The list endpoint is not used (filtering unproven).
- No CONFLICT with DES §4: every [V] claim there is consistent; the DES [U] on list filtering stays [U].

## GAPS
- OpenAI/OpenRouter probe error bodies are coded from the documented generic shapes; real calls only with RR_CONTRACT=1.
- Org-restricted wording for Claude Code.

## COST
tokens=~0 calls=1 live CLI, 7 doc fetches
