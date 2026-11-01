# Verified research: verify / rr affected (W2-C)

Date: 2026-11-01. Legend: [V] read in this session, [U] not verified.

## FACTS

claim | URL | status
---|---|---
Composer `autoload.psr-4` maps namespace prefix to directories relative to the package root; the prefix is NOT part of the file path (`Foo\` -> `src/`: `Foo\Bar\Baz` is `src/Bar/Baz.php`); prefixes end in `\`; a value may be an array of dirs; an empty prefix is a fallback dir | https://getcomposer.org/doc/04-schema.md#psr-4 | [V]
`autoload-dev` is where test namespaces (`MyLibrary\Tests\` -> `tests/`) go; root package only | https://getcomposer.org/doc/04-schema.md#psr-4 | [V]
`jest --findRelatedTests a.js b.js` runs the tests covering the given source files (space-separated, source files not test files); `--listTests` lists the test files Jest would run and exits; `--passWithNoTests` passes when no files are found | https://jestjs.io/docs/cli | [V]
The combination `--listTests --findRelatedTests <file>` is not documented together on the page (prose says listing "given the arguments") | https://jestjs.io/docs/cli | [U] (implemented; fake-runner tested only)
`vitest related <files>` runs only tests covering the source files; paths relative to root; static imports only, NOT dynamic `import(path)`; watch mode is the default so hooks need `--run` | https://vitest.dev/guide/cli.html | [V]
vitest has no documented list-only mode for `related`; behaviour of `related` with zero matches (exit code) is not stated | https://vitest.dev/guide/cli.html | [U]
pytest-testmon: `pytest --testmon` builds a dependency DB (`.testmondata`) from coverage and on later runs executes only affected tests; the page does not explain the mechanism or its reliability (defers to a blog post) | https://github.com/tarpas/pytest-testmon | [V]
`go list -deps` also lists all dependencies; `-test` also reports the test binaries (import path suffix `.test`); `Deps` = all (recursively) imported dependencies; `TestImports`/`XTestImports` = imports of internal/external test files; `-json=Field,...` limits output fields | https://pkg.go.dev/cmd/go#hdr-List_packages_or_modules (first 100k chars of 179k) | [V]
`go list -test -json=ImportPath,Dir,Deps ./...` emits, per package with tests, a `<pkg>.test` entry whose `Deps` contain the tested package (variants appear as `pkg [pkg.test]`) | scratch run on this repo, go 1.27.3 | [V]

## READ

- Composer schema page (psr-4, autoload-dev), jest CLI page, vitest CLI page, pytest-testmon README, `go` command docs (list section, first 100k chars).

## DESIGN CONSEQUENCES

- phpunit: PSR-4 resolves a changed file to its FQCN; tests = `<Class>Test.php` anywhere plus test files that mention the FQCN. No php needed.
- jest: one `--listTests --findRelatedTests` call per file, so a file with no related test is reported uncovered (=> full run). vitest: `related --run <source files>` is the only verified form; uncovered cannot be detected up front (selection_misses is the safety net).
- pytest: testmon is not required and its mechanism is undocumented here; selection is a static import graph (reverse closure), blind to dynamic imports.
- go: reverse graph from test-binary `Deps`; a changed non-Go file maps to its nearest enclosing package, otherwise uncovered.

## GAPS

- jest `--listTests` + `--findRelatedTests` combination, vitest zero-match exit code, and real jest/vitest/pytest/php runs: [U] (runtimes not installed; fake runners only).
- Per-test failure attribution: `TestResult.Failed` is coarse (all selected tests on non-zero exit).
- Policy adapters without a built-in adapter (`lint`) are skipped by `rr verify`.
- pytest relative imports and `conftest.py` fixtures chains are not followed.

## COST

~6 page fetches; no conflicts with DES §9.2. (DES says go uses `go list -deps` reversed: done via `-test` binaries' `Deps`.)

## GAPS (host-only close, fix round 4)

- An advisory run is not proof. `rr verify --close` started by an agent is journaled with `trusted:false`; `ComputeFacts` and `Close` count only a run started by a trusted actor (human, autonomy/runner, ci). Who really started a run is enforced by the flow (W4-A), not by this module.
- TOCTOU while the agent is alive (files changed between fingerprint and run, or by a still-running agent process) is not closed by this module; it is closed by running `verify.Close` only after the agent's processes have stopped.
- Adapter environment is an allowlist (HOME, TMPDIR, USER, LOGNAME, LANG, LC_ALL, TERM, TZ, SYSTEMROOT) plus PATH = the rr process PATH reduced to absolute directories outside the repository. Tools that need other variables (databases, tokens) will not see them.
- Built-in cache allowlist (`.phpunit.cache/**`, `.phpunit.result.cache`, `.pytest_cache/**`, `**/__pycache__/**`, `node_modules/.cache/**`, `var/cache/**`) is exempt from fingerprint equality and from task changes; anything else, ignored files included, must be identical before and after a run.
