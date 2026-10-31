# Verified research: research factory (W2-E)

Date: 2026-11-01. Legend: [V] page fetched in this session, [U] not verified.

## FACTS

claim | URL | status
---|---|---
Anthropic: each subagent needs "an objective, an output format, guidance on the tools and sources to use, and clear task boundaries"; vague briefs cause duplicated work and gaps | https://www.anthropic.com/engineering/multi-agent-research-system | [V]
Anthropic scaling rules: simple fact-finding 1 agent / 3-10 tool calls; direct comparison 2-4 subagents / 10-15 calls each; complex research more than 10 subagents | same | [V]
Anthropic: multi-agent systems use about 15x the tokens of chat (single agent about 4x) | same | [V]
llms.txt is a Markdown file `llms.txt` at the site root or any subpath; the proposal page is titled "v2"; order: optional BOM, H1 (only required part), blockquote summary, free Markdown, H2 file lists of `[name](url): notes`; an H2 "Optional" holds skippable links; the most specific file wins | https://llmstxt.org/ | [V]
Context7: the version is written in the prompt text ("How do I set up a Next.js 16 proxy? use context7"); Context7 "will automatically match the appropriate version"; example library IDs (`/vercel/next.js`) carry no version segment | https://github.com/upstash/context7 | [V]
Context7 behaviour when no version is given or the version is unknown (silent fallback to latest) | - | [U]

## READ

- https://www.anthropic.com/engineering/multi-agent-research-system
- https://llmstxt.org/
- https://github.com/upstash/context7 (README page only)

## CONFLICT

- DES §5.2 cites `llms.txt` with `@doc-version` as [V] (Next.js). The llmstxt.org spec has no `@doc-version` marker and no version field; if it exists it is a site convention, not part of the standard. The tech-docs-scout brief therefore asks for the version as stated in the document and to compare it with the lockfile.
- DES §5.2 says Context7 takes the version "in the prompt" [V]: confirmed, but the README shows no API-level version parameter, so the returned version cannot be machine-checked from the request; the scout must verify it from the returned text. Context7 stays behind `research.tech_docs.context7` (default false, errata #2).

## GAPS

- Context7 HTTP/MCP parameter list (a `/org/project/version` ID form) not found on the README page.
- Whether the 15x figure applies to Haiku-class scouts (DES §5.1 measured 57k average) not verified.

## COST

tokens=~25k calls=3
