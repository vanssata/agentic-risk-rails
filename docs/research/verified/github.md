# GitHub (W3-B) — verified facts

Checked 2026-11-01 against docs.github.com. [V] = read on the page; [U] = not confirmed.

## FACTS
- [V] Branch rules: `GET /repos/{o}/{r}/rules/branches/{branch}` returns an array of rule objects `{type, parameters?}`; only rules of `active` rulesets, repo and org level; the branch need not exist. https://docs.github.com/en/rest/repos/rules
- [V] `pull_request` rule parameters: `required_approving_review_count`, `dismiss_stale_reviews_on_push`, `require_code_owner_review`, `require_last_push_approval`, `required_review_thread_resolution`, `required_reviewers[{file_patterns, minimum_approvals, reviewer}]`, `allowed_merge_methods`, `dismissal_restriction`. Same page.
- [V] `required_status_checks` rule: `required_status_checks[{context, integration_id?}]`, `strict_required_status_checks_policy`, `do_not_enforce_on_create`. Same page.
- [V] Create ruleset body: `name`, `target` (branch|tag|push), `enforcement` (disabled|active|evaluate; evaluate = Enterprise), `bypass_actors[{actor_id, actor_type, bypass_mode}]`, `conditions.ref_name.include` accepts `~DEFAULT_BRANCH`, `rules[]`. Same page.
- [V] Required reviewers by file pattern: up to 15 teams, 0-10 approvals each, team needs write access, not available on user-owned repos. https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- [V] Rules "Require approval of the most recent reviewable push", "Dismiss stale approvals", code owner review exist (same page).
- [V] `GET /repos/{o}/{r}/pulls/{n}/reviews`: chronological, `per_page` max 100 (default 30), fields `state`, `user` (nullable, `user.type`), `commit_id`. https://docs.github.com/en/rest/pulls/reviews
- [V] `GET /orgs/{org}/teams/{slug}/memberships/{user}`: 200 `{role, state: active|pending}`; 404 = no membership; caller must be an org member and the team visible. https://docs.github.com/en/rest/teams/members
- [V] `GET /repos/{o}/{r}/contents/{path}?ref=`: ref optional (default branch); 404 "Resource not found"; files up to 1 MB fully supported. https://docs.github.com/en/rest/repos/contents
- [V] CODEOWNERS: `.github/`, root or `docs/` (first found); must be on the PR base branch; last matching pattern wins; teams as `@org/team`, need explicit write access; invalid lines are skipped. https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

## READ (how the code uses it)
- Rules via `rules/branches/{default}`; reviews paged; membership 404 means not a member; contents 404 means `core.ErrNotFound`.
- Bot = `user.type == "Bot"` or login ending `[bot]` (the type value itself is [U] on the page; the suffix is a second signal). A null user counts as bot.

## GAPS
- [U] Plan availability of required reviewers by file pattern (the page only says: not on user-owned repos) and bypass behaviour. The check does not depend on it: the minimum is CODEOWNERS + code-owner review + required status check.
- [U] Whether GITHUB_TOKEN / App token can submit an APPROVED review. Not relied on: a review from a non-member never counts.
- [U] `bypass_actors` are not part of the `rules/branches` response; the live check cannot see bypass. The generated ruleset has empty `bypass_actors`.
- [U] `pull_request_review` events run on the merge ref; the status attaches to that run, not necessarily the PR head SHA. The `pull_request` run is re-triggered by the human via "Re-run".

## COST
Policy check: 1 PR read + ceil(reviews/100) review pages + at most 1 membership call per distinct approver + 1 contents read. Sync remote: 1 call for rules + 1 per distinct ruleset + 1 contents read.

## ROUND 1 ADDITIONS
- [V] GitHub Actions app id is 15368 (`gh api apps/github-actions` returns id 15368, slug github-actions; the docs page https://docs.github.com/en/rest/apps/apps#get-an-app documents the endpoint, not the value). `required_status_checks[].integration_id` is "the optional integration ID that this status check must originate from" (https://docs.github.com/en/rest/repos/rules). The generated ruleset and `MissingRules` pin it.
- [V] `GET /repos/{o}/{r}/rulesets/{id}` returns `bypass_actors` only if the caller has write access to the ruleset (https://docs.github.com/en/rest/repos/rules). Field absent means unverifiable, so L>=2 is refused.
- [U] `ruleset_id`, `ruleset_source_type`, `ruleset_source` on `rules/branches` items are not on the docs page (observed API behaviour); a rule without `ruleset_id` is a refusal. Org rulesets are read with `GET /orgs/{org}/rulesets/{id}` [U].
- [V] Team membership needs org `members:read`, which the default GITHUB_TOKEN lacks, so the workflow uses `secrets.RR_GITHUB_TOKEN` (https://docs.github.com/en/rest/teams/members). 403 = token lacks the scope (error); 404 = not a member or team invisible (not a member, red).
- [V] Action pins resolved with `gh api repos/actions/<name>/commits/<tag> --jq .sha` (https://docs.github.com/en/rest/commits/commits): actions/checkout v5 = fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09, actions/setup-go v6 = 924ae3a1cded613372ab5595356fb5720e22ba16.
- [V] `pull_request_target` runs the workflow file from the base branch (https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows); checked-out PR code must never be executed there.
- GAP: the rr version in the templates is a constant refreshed on release; an approval submitted after the check ran needs a re-run of the job.

## WAVE 4 (W4-C) ADDITIONS
- [V] Labels on a PR: `POST /repos/{o}/{r}/issues/{n}/labels` with `{"labels":[...]}` (bare array also accepted) adds to existing labels; "every pull request is an issue", so n is the PR number. 200 = full label list; 404, 410, 422 are errors. https://docs.github.com/en/rest/issues/labels
- [V] `GET /repos/{o}/{r}/branches/{branch}`: `commit.sha` is required in the response; missing branch = 404 "Resource not found". https://docs.github.com/en/rest/branches/branches
- [U] Whether GitHub accepts `rr%2Fx` (escaped slash) in `{branch}`: go-github escapes it with url.PathEscape and the client does the same; not confirmed on the docs page.
- [V] `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>` add runtime config, override config files, but `git -c` wins over them; a missing key or value is an error. https://git-scm.com/docs/git-config
- [U] `http.<url>.extraHeader` (URL-scoped, so the header does not go to other hosts) is not on the part of the git-config page that was read (page truncated); known from git behaviour and used by actions/checkout. Tested by construction only (no network in tests).
- Choice: token only in the child git's environment (`GIT_CONFIG_*`, value `AUTHORIZATION: basic base64(x-access-token:TOKEN)`), never argv or URL. Residual: readable by the same uid via /proc/<pid>/environ for the lifetime of the push. A credential helper would need an executable and has the same exposure.
- [V] `uploadpack.packObjectsHook` "is only respected when it is specified in protected configuration" (not repo config). https://git-scm.com/docs/git-config
- Push never runs from the agent's repo: fetch `refs/heads/<b>` (`--no-tags`) into a fresh bare repo with our own config, push from there (`--no-follow-tags`, `push.gpgSign=false`, no push options). The fetch's upload-pack runs in the agent repo; `-c` does NOT reach it (GIT_TRACE shows `unset GIT_CONFIG_PARAMETERS ...; git-upload-pack`, [V] observed, earlier assumption refuted), so safety rests on upload-pack running no repo-controlled code (packObjectsHook is protected config). Source with `.git` not a real directory, any symlink under `.git`, `commondir`, or `objects/info/(http-)alternates` is refused, before and after the fetch. Residual: readable by the same uid via /proc/<pid>/environ for the lifetime of the push. A credential helper would need an executable and has the same exposure.
- [V] `uploadpack.packObjectsHook` "is only respected when it is specified in protected configuration" (not repo config). https://git-scm.com/docs/git-config
- Push never runs from the agent's repo: fetch `refs/heads/<b>` (`--no-tags`) into a fresh bare repo with our own config, push from there (`--no-follow-tags`, `push.gpgSign=false`, no push options). The fetch's upload-pack runs in the agent repo; `-c` hardening is propagated to it via GIT_CONFIG_PARAMETERS [U: exact propagation not read on a docs page]. Source with `.git` not a directory, `commondir`, or `objects/info/(http-)alternates` is refused. Residual: alternates could be added between the check and upload-pack.
