# Verified facts: triage (W2-A)

Method: local reading of the claude-agentic prototype (paths below, repo `/Store/ProjectToBuild/claude-agentic`) and DES. No web sources. Tags: [V] = read in the file named, [U] = not verified by running it.

## FACTS
- Six axes 0..2, W = sum; light W<=2, guarded 3-7, full W>=8 or reversibility=2 or domain=2; both =2 -> full_irreversible | docs/weight.md "Modes" ; skills/ai-task/weight.py:compute | [V]
- A measurement is a floor; a declaration below it is replaced; declaring never lowers | docs/weight.md "What is measured" ; weight.py:compute | [V]
- UNKNOWN (neither measured nor declared) scores 1 | weight.json rules.unknown_scores ; weight.py:compute | [V]
- Scope: reference count of each file (basename as whole word; path for .yaml/.twig/.json...), test files and the file itself not counted; bands [0,5]; hot_paths -> 2; new file -> 0 | weight.py:_scope | [V]
- Rescore is upward only and only on reversibility+domain; content hunk in a needs_step file matching irreversible_content -> reversibility 2 | docs/weight.md "Reversibility and domain"; weight.json rules.rescore_axes | [V]
- All-new files -> behaviour 0; tests-only -> behaviour/domain/novelty 0; manifest among files -> novelty >=1; keyword in goal/file text -> behaviour >=1 | weight.py:_measure | [V]
- Coverage: a code file is covered when some test file's basename contains its identifier; 0 if all covered, 1 if some, 2 if none; no code files -> 0 | weight.py:_measure | [V]
- 13 SQ1 cases = the 13 test functions of tests/test_weight.py::TestSQ1 (two have two checks) | tests/test_weight.py:60-170 | [V]
- Mode only rises; lowering is a human act | docs/weight.md "Changing the table" | [V]
- doublestar `*` does not cross `/`; `**` does; patterns without `/` also match the basename (internal/globs.Match) | docs/research/verified/policy.md | [V]

## READ
- /Store/ProjectToBuild/claude-agentic/docs/weight.md, docs/known-risks.md, tests/test_weight.py, skills/ai-task/weight.py, skills/ai-init/templates/.ai/policies/weight.json
- docs/design/research-fable.md 2.3, 3.2, 7.1, 8.1, 13; errata.md; internal/core/{policy,types,defaults}.go

## CONFLICTS / GAPS (DES vs prototype)
- GAP: DES has no `hints` (auth-shaped path +1, "pipeline" files -> behaviour). Emulated in the golden policy by putting such paths in domain/irreversible globs; the CLAUDE.md case declares behaviour=1.
- GAP: DES has no `code_globs` and no manifest list. Triage uses a built-in code-extension list and built-in manifest basenames (composer.*, package*.json, go.mod/sum, ...).
- CONFLICT (inside prototype): weight.json says full_irreversible "when ... or irreversible_content"; weight.md says such a migration is `full`, not full_irreversible. DES hard_floors say full_irreversible only for both axes =2. Followed DES + weight.md: content raises reversibility to 2 only.
- GAP: scope grep budget (10 files, 5 s) and "common word" rule (known risk FC-D1) are not ported; a common identifier over-counts scope (errs upward, safe).
- GAP: DES 2.3 step 5 says rescore scope by diff files, but DES 3.2 `rescore.axes` lists reversibility+domain and the prototype never rescores scope. Followed 3.2 (axes from policy).
- known-risks.md has no weight-specific entry; its guard-regex limits apply to path globs (tripwire, not boundary).

## COST
tokens=n/a calls=n/a (local reading only)
