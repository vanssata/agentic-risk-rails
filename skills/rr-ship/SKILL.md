---
name: rr-ship
description: Close a RiskRails task and prepare it for review. Use when the implementation is done and needs verification before a PR.
---

# rr-ship

1. `rr status` (MCP tool `status`) - confirm the open task and its mode.
2. `rr verify --task <task>` - must pass; do not bypass. The close run is done by the host, not by you.
3. Summarise changes and any `NEEDS_CONTEXT` points for the reviewer.
