---
name: rr-ship
description: Close a RiskRails task and prepare it for review. Use when the implementation is done and needs verification before a PR.
---

# rr-ship

1. `rr status` (MCP tool `status`) - confirm the open task and its mode.
2. `rr verify --task <task>` - must pass; do not bypass. The close run is done by the host, not by you.
3. Mode `guarded` or heavier: `rr task close` is refused without an accepted written plan
   (`PLAN_MISSING`) and a last review verdict of PASS (`REVIEW_MISSING`). The host gets there with
   `rr task research`, `rr task accept --plan <file>` and `rr task build` (its factory review is the
   verdict); you do not run them. If either is missing, say which in your summary.
4. Summarise changes and any `NEEDS_CONTEXT` points for the reviewer.

Under the unattended runner (`$RR_LEVEL` is L2 or higher) skip 1-3: the task is not visible
inside your container and the runner closes it. Run the project's tests and end your report
with the `STATUS:` line the brief asks for.
