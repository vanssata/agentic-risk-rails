# AGENTS.md — RiskRails v4 (`rr`, Go)

Risk engine + enforcement for AI coding agents. Design: `docs/design/research-fable.md` (DES).
Plan and waves: `docs/plan/implementation-plan.md`. Decisions: `docs/adr/`. DES fixes: `docs/design/errata.md`.

## Layout
- `cmd/rr/main.go` — never edit. Add commands in `cmd/rr/cmd_<module>.go` via `cli.Register` in `init()`.
- `internal/core/` — frozen contracts (types, policy schema, interfaces). Change only between waves.
- `internal/core/fakes/` — fakes for every interface; use them until the real module exists.
- `internal/<module>/` — one owner per wave. Events in `internal/<module>/events.go` (`journal.MustRegister`).
- Generators register with `internal/sync.Register` in `init()`.
- `internal/testutil/` — `Golden` (`go test ./... -update`), `GitRepo`, `CopyFixture`, `FakeBin`.
- `testdata/php-symfony/` — reference project; its `riskrails.yaml` is the DES §3.2 schema contract.

## Gate
`make check` = gofmt + go vet + golangci-lint + `go test ./... -race`. Nothing is DONE unless it is green.

## Code rules
1. **Think before coding.** You cannot ask the owner mid-task. Write assumptions in your report
   (`ASSUMPTIONS`). An ambiguity that changes the design → stop that point, report `NEEDS_CONTEXT`.
   If a simpler approach than the brief exists, say so in the report.
2. **Simplicity first.** Minimum code that passes the acceptance tests. No unrequested features,
   options, configurability or abstractions; no handling of impossible errors. If 200 lines could be 50,
   rewrite before reporting. Exception: `internal/core` interfaces and fakes are deliberate — use them,
   don't bypass or "simplify" them.
3. **Surgical changes** (fix rounds, edits to others' code): touch only the lines a finding requires;
   no adjacent cleanups; match existing style; remove only orphans your change created.
4. **Verifiable goals.** Test first, then code, then green. Every step ends with a check you ran.

## Go conventions
- Errors: wrap with `%w`, no panics outside `init()` registration. Security paths are fail-closed:
  any internal error in guard/policy/autonomy ⇒ deny/refuse.
- Pure where possible: generators and triage take input structs and return values; no globals besides registries.
- Tests: table-driven, `testify/assert|require`, golden files under the package's `testdata/`.
- No new dependencies and no edits to `go.mod`/`go.sum` — request them in `CORE_CHANGE_REQUESTS`.
- Facts from the web go to `docs/research/verified/<module>.md` with URL and [V]/[U]; never cite from memory.

## Safety
- Never write to `~/.config/riskrails`, `~/.cache/riskrails`, or real runtime configs outside temp dirs.
- Contract tests against real `claude`/`codex` binaries run only with `RR_CONTRACT=1`.
- Do not copy content of real transcripts or secrets into the repo; fixtures are synthetic.
