# Verified facts: policy (W1-A)

Note: no claim below has a web URL. Every FACT is a local experiment, tagged `exp [V]`, with the command or test case named in the claim (no `exp` claim is [U]).

Method: experiments run locally on 2026-10-31 (go 1.27.3, doublestar/v4 v4.10.4, yaml.v3 v3.0.1, system git). Source "exp" = reproducible test in the session; the exact cases are listed in each claim.

## FACTS
- doublestar/v4 `Match("src/Payment/**", f)` is true for `src/Payment/a.php`, `src/Payment/x/y.php` and `src/Payment` itself | exp (doublestar v4.10.4) | [V]
- `Match("src/Payment/*.php", "src/Payment/x/y.php")` is false: `*` does not cross `/` | exp | [V]
- `Match(".env*", ".env")` and `.env.local` true; `config/.env` false (anchored at root, `*` does not cross `/`); `**/.env*` matches both `.env` and `config/.env` | exp | [V]
- `Match("migrations/**", "migrations/2020/a.sql")` true; `src/**/*.php` matches `src/a.php` (zero directories) | exp | [V]
- `*` matches a leading dot (no hidden-file special case) | exp (`.env*`) | [V]
- A malformed pattern (`[`) returns `doublestar.ErrBadPattern` | exp | [V]
- `~/...` and `$name` entries never match repo-relative paths | exp (`~/.ssh/**` vs `x`) | [V]
- git pathspec (no `:(glob)` magic): `git ls-files -- 'src/P/*.php'` returns `src/P/a.php` AND `src/P/x/b.php` (`*` crosses `/`); with `:(glob)` only `src/P/a.php` | exp, git ls-files | [V]
- So doublestar `*` is NARROWER than a bare git pathspec `*`. RiskRails uses doublestar for every glob decision, never git pathspec, so `src/Payment/**` -> `src/Payment/*.php` removes nested files from the set and is LOOSEN | exp | [V]
- `git show origin/main:riskrails.yaml` with no remote and no ref: `fatal: invalid object name 'origin/main'`, exit 128 | exp | [V]
- `git show main:riskrails.yaml` works on the local branch (exit 0); with remote configured but `refs/remotes/origin/main` not fetched the result is the same fatal error | exp | [V]
- `git show main:nofile.yaml` (file absent) is also exit 128 with `path ... does not exist`, so exit codes do not distinguish "bad ref" from "absent file"; use `git ls-tree --name-only <ref> -- <path>` (empty output + exit 0 = absent, exit 128 = bad ref) | exp | [V]
- `git symbolic-ref refs/remotes/origin/HEAD` fails (exit 128) when origin/HEAD was never set | exp | [V]
- yaml.v3 `Decoder.KnownFields(true)` applies inside map values and slice elements: unknown keys in `risk.axes.scope`, `risk.modes.light`, `verify.adapters[]`, `hard_floors[]` are errors | exp | [V]
- yaml.v3 duplicate mapping keys are an error; an empty document returns `io.EOF` from `Decode` (loader must treat as empty policy) | exp | [V]
- `core.Axis`/`core.Mode` map keys go through `UnmarshalText`, so unknown axis names are rejected; `core.Tier` upper-cases input, so `effort: {fast: low}` is accepted as FAST | exp | [V]

## READ
- docs/design/research-fable.md §3.3, §3.4 (steps 1 and 3), docs/design/errata.md #3, #4, internal/core/{policy,defaults,interfaces,types}.go

## TRUST
- `refs/remotes/origin/*` and `origin/HEAD` are writable by the agent locally (`git update-ref`). Until the wave-3 runner pins a trusted SHA (or fetches), the local `InForce` is a tripwire, not a boundary. In CI, `--base` must be a SHA obtained from the hosting API. `ResolveRef` accepts only HEAD, `refs/...`, an unambiguous short name, or a full hex SHA that is not also a ref name; revision syntax (`~ ^ @ : { ..`) is rejected.

## GAPS
- Guard (W1-C) must match globs with the same doublestar semantics as the policy differ; a different matcher reopens the narrowing hole | open | [U]
- Which branch is "default" when `origin/HEAD` is unset is not defined by DES (circular if read from the policy itself); implemented as origin/HEAD, then `main`, then `master` | open | [U]

## COST
- Experiments only: no network, no tokens beyond the session.
