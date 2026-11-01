---
name: rr-release
description: Prepare a release with RiskRails gates. Use when asked to tag, publish or cut a release.
---

# rr-release

1. `rr status` - no open task may be left in a failed state.
2. `rr verify` - a full run is required for a release.
3. Run `rr release preflight` and `rr changelog --check` (dry-run only); publishing itself is done by CI, never from the agent session.
