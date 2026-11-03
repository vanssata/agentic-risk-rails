---
name: rr-build
description: Start or continue a RiskRails task. Use when about to implement a change - triage first, then build within the mode rr reports.
---

# rr-build

1. Run `rr triage --json --files <files you expect to touch> --goal "<goal>"` (MCP tool `triage`).
2. Follow the reported `mode`; do not lower an axis the triage raised.
3. Mode `light`: implement test first. Check progress with `rr affected` (in the shell, inside the sandbox).
4. Mode `guarded` or heavier: do not implement the change yourself. Write the plan and stop:
   - A YAML file outside the checkout (for example `/tmp/<task>-plan.yaml`) with
     `steps:` - each step has `id`, `brief`, `files` (exact repo-relative paths, no globs),
     optional `tests` and `after` (ids of steps it must follow). Steps that share a file need `after`.
     Every file and test must lie inside the task scope.
   - Cite the research brief (`.rr/run/<task>.research.md`, if the human ran `rr task research`) in each `brief`.
   - Tell the human to run, on the host: `rr task accept --plan <file>`, then `rr task build`
     (workers implement each step in their own worktree, a spec and a quality reviewer check it),
     then `rr task close`. These are human commands: they are refused in an agent shell.
5. Before finishing run `rr verify --task <task>` and fix what it reports.
   Under the unattended runner (`$RR_LEVEL` is L2 or higher) the task journal is outside your
   container, so `rr verify` cannot see the task: run the project's tests directly instead
   (e.g. `go test ./...`); the runner verifies and closes on the host.

Never edit policy or generated manifests to get past a refusal; report it instead.
