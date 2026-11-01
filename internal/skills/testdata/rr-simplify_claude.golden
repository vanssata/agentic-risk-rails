---
name: rr-simplify
description: Simplify the changed code (reuse, simplification, efficiency) after a green build. Use before shipping; not for bug hunting.
---

# rr-simplify

1. Run `rr simplify` (add file paths to override the git diff). It prints JSON: `files` to review, `ignored`, and per-tool `findings` (jscpd duplicates, ast-grep rules). A tool with status `skipped: ...` just was not available.
2. One pass over `files` only: remove duplication, reuse existing helpers, drop needless code, fix obvious inefficiency. No behaviour changes, no bug hunting, no new features.
3. A file containing the marker `simplify-ignore` is excluded by `rr simplify`; never touch it.
4. Re-run the tests (`rr affected`, then `rr verify`) and keep the change only if green.
