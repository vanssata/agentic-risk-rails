---
name: rr-build
description: Start or continue a RiskRails task. Use when about to implement a change - triage first, then build within the mode rr reports.
---

# rr-build

1. Run `rr triage --json --files <files you expect to touch> --goal "<goal>"` (MCP tool `triage`).
2. Follow the reported `mode`; do not lower an axis the triage raised.
3. Implement test first. Check progress with `rr affected` (in the shell, inside the sandbox).
4. Before finishing run `rr verify --task <task>` and fix what it reports.

Never edit policy or generated manifests to get past a refusal; report it instead.
