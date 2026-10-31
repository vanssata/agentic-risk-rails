# RiskRails v4 — план за имплементация с паралелни субагенти

Източник: `docs/design/research-fable.md` (по-нататък **DES**, секциите са `§N`). Дата: 2026-10-31.
Изпълнители: субагенти на **Sonnet 5.5** (`model: sonnet`), всеки в собствен git worktree (`isolation: worktree`), всеки прави **research → код → тестове** в своя модул. Оркестраторът (главната сесия) замразява договорите, мърджва вълните и пуска gate-овете.

Планът прилага към себе си правилата от DES §6: DAG по файлова собственост, вълна = непресичащи се файлове, работник = свеж агент с brief/report, двустепенно review, атомарен commit на стъпка.

---

## 0. Изходно състояние и предпоставки

| Факт (проверен 2026-10-31) | Последствие |
|---|---|
| Директорията **не е git repo** | Вълна 0 прави `git init`; без това `isolation: worktree` не работи |
| **Go не е инсталиран** | Вълна 0 инсталира последния стабилен Go в `~/.local/go` (без sudo) и го добавя в `.envrc` |
| `claude`, `codex` са в `~/.local/bin`; `gemini` липсва | contract тестовете за Claude/Codex може да вървят срещу живите бинари; за Gemini/Cursor — само golden + документация |
| `bwrap`, `docker` са налични | EACCES тестът от P0 и контейнерът за L≥2 са изпълними локално |
| `php`/`composer` липсват | phpunit/composer адаптерите се тестват с fixture repo + fake binaries в `testdata/bin/`; реален run — в CI с `shivammathur/setup-php` |
| `../claude-agentic/docs/weight.md` + `tests/test_weight.py::TestSQ1` съществуват | 13-те SQ1 случая се пренасят като golden таблица за triage (P1) |

### 0.1 Решения по DES §14, приети по подразбиране (собственикът може да ги смени преди вълна 1)

| # | Приет default | Засяга |
|---|---|---|
| 1 GitHub план | минимумът е CODEOWNERS + required status check; `sync --check --remote` отказва L≥2, ако file-pattern reviewers липсват | W3-B |
| 2 Без remote | ≤ L1, без локален policy lock | W3-A |
| 3 EXPERT | остава в схемата като опционален tier; липсата му е нормално състояние | W2-B |
| 4 Context7 | зад флаг `research.tech_docs.context7: false`; задължителни са `vendor/` + `llms.txt` | W2-E |
| 5 Serena | само външен MCP, никога вграждане | W3-D |
| 6 Пълен suite при close | остава (ADR-10) | W2-C |
| 9 Име | ново repo, бинар `rr`, без `rr adopt` | — |
| 10 Език | Go | всички |

---

## 1. Стратегия за паралелизъм

### 1.1 Правила, които правят паралелното писане безопасно

1. **Договорите се замразяват преди вълна 1.** `internal/core` (типове и интерфейси), `go.mod` с всички зависимости, регистър на CLI команди и регистър на journal събития — пише ги само вълна 0. Агент, на когото му трябва промяна в `internal/core` или нова зависимост, връща `NEEDS_CONTEXT` с конкретно предложение; оркестраторът я прави между вълните.
2. **Всеки агент притежава директории, не файлове поотделно.** Списъкът `OWNS` в brief-а е изчерпателен; писане извън него е нарушение, което review-то връща като BLOCKER.
3. **Без споделени „hub“ файлове.**
   - CLI: всеки модул добавя `cmd/rr/cmd_<module>.go`, който се регистрира през `func init() { cli.Register(...) }`. Никой не пипа `cmd/rr/main.go`.
   - Journal събития: всеки модул декларира своите в `internal/<module>/events.go` с `journal.MustRegister(...)` в `init()`.
   - Генератори за `rr sync`: всеки адаптер имплементира `core.Generator` и се регистрира в `init()`.
4. **Зависимост между модули само през интерфейс от `internal/core`.** Ако модул B още не е готов, A тества с fake от `internal/core/fakes`. Реалното свързване е във вълна 4.
5. **`go.sum` конфликти** решава само оркестраторът при merge (`go mod tidy` след всяка вълна).

### 1.1a Правила за код (адаптирани от multica-ai/andrej-karpathy-skills)

Записани в `AGENTS.md` и в шаблона на brief-а (§8). Адаптацията е за паралелни фонови агенти, които не могат да питат:

1. **Мисли преди код.** Предположенията се записват в report-а (`ASSUMPTIONS`). Двусмислие, което променя дизайна → `NEEDS_CONTEXT`, не тих избор. По-прост вариант от brief-а → предлага се в report-а.
2. **Простота първо.** Минимум код за acceptance тестовете; без функции, настройки и „гъвкавост“, които не са поискани; без обработка на невъзможни грешки. **Изключение:** интерфейсите и fakes в `internal/core` са нарочни (паралелна работа) — не се „опростяват“.
3. **Хирургични промени** (fix рундове след review): само редовете, които находката изисква; без съседни подобрения.
4. **Цел, която се проверява.** Всяка стъпка → тест → код → зелено; без тест няма DONE.

Механични проверки (по-силни от насоките): `gofmt`, `go vet`, `golangci-lint run` с `.golangci.yml` от вълна 0 — задължителни в gate-а на всяка вълна и в acceptance на всеки агент.

### 1.2 Как всеки агент комбинира research и код

Всеки brief има три фази с бюджет:

| Фаза | Дял | Изход |
|---|---|---|
| R — research | ≤ 25% | `docs/research/verified/<module>.md` в схемата от DES §5.4 (FACTS / READ / GAPS / COST), с URL и [V]/[U]. Задължително: проверка на всяко **[U]** от DES, което модулът му ползва. Ако факт опровергава DES — агентът спира кода по тази точка и го записва като `CONFLICT` в report-а. |
| C — код | ~60% | модулът + CLI командата + events |
| T — тестове | ~15% (+TDD по време на C) | unit + golden + (където има) contract тест срещу живия бинар |

Report (≤ 1.5k токена, DES §6): `STATUS: DONE | DONE_WITH_CONCERNS | BLOCKED | NEEDS_CONTEXT`, `FILES`, `TESTS` (команда + резултат), `CONFLICTS` с DES, `GAPS`, `CORE_CHANGE_REQUESTS`.

### 1.3 Лимити

- ≤ 6 едновременни агента на вълна (DES §6 казва ≤3 на BALANCED за реален проект; тук задачите са разделени по директории и се ревюират, затова 5–6).
- `max_turns` ~ неограничен от harness-а, но целта е ≤ 1.5k реда код на агент.
- Gate след всяка вълна: `make check` (= `gofmt -l` празно, `go vet`, `golangci-lint run`, `go test ./... -race`) зелен + review (§6).

---

## 2. Вълна 0 — Bootstrap и договори (оркестратор, серийно, ~1 ден)

Не се паралелизира: всичко след нея зависи от тези файлове.

| # | Стъпка | Файлове |
|---|---|---|
| 0.1 | `git init -b main`, `.gitignore` (`.rr/run/`, `.rr/index.json`, `dist/`) | `.gitignore` |
| 0.2 | Go в `~/.local/go`, PATH в `.envrc`, `go mod init github.com/<owner>/agentic-risk-rails` | `go.mod`, `.envrc` |
| 0.3 | Зависимости (замразени): `mvdan.cc/sh/v3`, `github.com/spf13/cobra`, `gopkg.in/yaml.v3` (или `goccy/go-yaml` — решава се тук), `github.com/bmatcuk/doublestar/v4`, `github.com/modelcontextprotocol/go-sdk`, `github.com/pelletier/go-toml/v2`, `github.com/google/go-github/v7x`, `github.com/stretchr/testify` | `go.mod`, `go.sum`, `tools.go` |
| 0.4 | `internal/core`: типове `Tier`, `Mode`, `Level`, `Decision{Allow,Ask,Deny}`, `Axis`, `Weight`, `Event` envelope (`schema, task, actor, via, policy_sha, tiers_effective, prev_sha256`); `Policy` struct = схемата от DES §3.2 (само полета, без логика) | `internal/core/*.go` |
| 0.5 | Интерфейси: `PolicyResolver`, `PolicyDiffer`, `Journal`, `Guard`, `RuntimeAdapter` (ParseHookInput / RenderHookOutput / Generators), `Generator` (`Render(effective) []File`), `VerifyAdapter` (DES §9.2), `ReleaseAdapter` (DES §9.1), `TranscriptParser`, `ModelProber`, `Scout`, `WorkerRunner`, `Hosting` (GitHub API) | `internal/core/interfaces.go` |
| 0.6 | Fakes за всеки интерфейс | `internal/core/fakes/` |
| 0.7 | CLI регистър + `cmd/rr/main.go`, `rr version` | `internal/cli/`, `cmd/rr/main.go` |
| 0.8 | Journal API (само сигнатури + in-memory fake) и регистър на събития | `internal/journal/registry.go` |
| 0.9 | `rr sync` рамка: събира регистрираните `Generator`-и, пише файлове, `--check` = diff срещу диска | `internal/sync/` |
| 0.10 | Test helpers: golden (`-update` флаг), temp git repo, fake бинари | `internal/testutil/` |
| 0.11 | Fixture: PHP/Symfony repo с `riskrails.yaml` от DES §3.2, `composer.json/lock`, `src/Payment`, `migrations/`, `tests/` | `testdata/php-symfony/` |
| 0.12 | `AGENTS.md` (≤ 60 реда, вкл. правилата от §1.1a), ADR-1…11 от DES §12 като `docs/adr/0001-…md`, `Makefile` (`make check`), `.golangci.yml`, `.github/workflows/ci.yml` | |
| 0.13 | Commit `chore: bootstrap + frozen contracts`; tag `wave-0` | |

**Gate 0:** `go build ./...` зелено; `rr version` работи; `rr sync --check` зелено с нула генератора.

---

## 3. Вълна 1 — P0 Core (5 агента паралелно, ~1–1.5 седмици)

```
          ┌── W1-A policy ──┐
wave-0 ───┼── W1-B journal ─┤
          ├── W1-C guard ───┼──► Gate 1 (P0)
          ├── W1-D claude ──┤
          └── W1-E codex ───┘
```

### W1-A — `policy`: схема, resolver, LOOSEN diff
- **OWNS:** `internal/policy/**`, `cmd/rr/cmd_policy.go`, `docs/research/verified/policy.md`
- **Research:** семантика на `doublestar` срещу git pathspec; как `git show origin/<branch>:file` се държи без remote; кои полета от §3.2 нямат посока (DES §3.4 т.1 — всички трябва да са в изрична таблица).
- **Код:** strict YAML парсване (непознат ключ = грешка); safe defaults (празен файл = най-строго); `Tighten(layers...)` монотонно сливане по поле с таблица на посоките; `Diff(base, candidate, lsFiles) → TIGHTEN|LOOSEN|MIXED` с glob-множества върху `git ls-files`; `InForce()` от default branch; ceiling loader + sha256; `rr policy diff --base`, `rr policy check --base` (локалната част, без reviews API).
- **Acceptance:** таблично тестване на всяко поле в двете посоки; `src/Payment/**` → `src/Payment/*.php` е LOOSEN; MIXED = LOOSEN; поле без посока → всяка промяна LOOSEN; property тест: `Tighten(a, b)` никога не е по-слабо от `a` или `b`.

### W1-B — `journal` + `status` / `doctor` / `rebuild`
- **OWNS:** `internal/journal/**` (без `registry.go`, `events_core.go` от вълна 0), `internal/projection/**`, `cmd/rr/cmd_status.go`, `cmd/rr/cmd_doctor.go`, `cmd/rr/cmd_rebuild.go`
- **Research:** atomic append + fsync на Linux/macOS; file locking (`flock`) при паралелни hook процеси; как AI-DLC прави event registry (DES §8.4 цитира 131 събития).
- **Код:** hash-chained JSONL (`prev_sha256`), audit-first API (`Append` преди state промяна, връща грешка → извикващият не прави промяната); `.rr/run/<task>.jsonl` и `.rr/tasks/`; `REFUSE {TASK_IN_FLIGHT}`; проекции `status`, `risks`; `rr doctor` (chain + `task.md`), `rr rebuild`; тест за задължителните събития от DES §16.1.
- **Acceptance:** подмяна на ред в средата се хваща; 50 паралелни `Append` от отделни процеси не губят и не чупят chain-а; непознато поле в стар event се пропуска.

### W1-C — `guard`: shell AST, paths, egress
- **OWNS:** `internal/guard/**`, `cmd/rr/cmd_guard.go`, `internal/guard/testdata/corpus/**`
- **Research:** API на `mvdan/sh/v3/syntax`; публични bypass техники за command guards (command substitution, `eval`, `bash -c`, `env`, `xargs`, heredoc, `$IFS`, алиаси, `\git`, абсолютни пътища, `git -c`); как Claude Code третира „too complex“ (DES §11, [U]).
- **Код:** парс → обхождане на всички `CallExpr` вкл. вложени; нормализация на командата; съпоставяне deny > ask > allow; `unlisted` и неразпознат възел → ask (L0/L1) / deny (L≥2); path правила за Edit/Write/Read (protected_paths, secret_reads); egress — извличане на хостове от `curl/wget/git clone/composer` аргументи; edit на `riskrails.yaml` → `PolicyDiffer` (fake до вълна 4) → LOOSEN = deny; fail-closed обвивка (panic/timeout → deny); `rr guard --event <name> --stdin` с вход/изход в неутрален формат (`core.ToolCall` / `core.Verdict`).
- **Acceptance:** корпус ≥ 150 команди (allow/ask/deny по очакване) като golden; fuzz тест (`go test -fuzz`) без panic; p99 < 5 ms на команда (benchmark).

### W1-D — адаптер **Claude Code** (hooks + генератори + sandbox)
- **OWNS:** `internal/adapters/claude/**`, `cmd/rr/link_claude.go` (`import _`), `docs/research/verified/claude-code.md`; регистрира се с `runtimes.Register`
- **Research (живи docs + `claude --version`):** точен формат на PreToolUse stdin/stdout JSON и exit 2; `onFailure: block` и timeout; `permissions` allow/ask/deny синтаксис; sandbox секцията в settings (`failIfUnavailable`, filesystem read/write deny); дали PreToolUse input за `Agent`/`Task` носи `model` (DES §4.5 [U]); subagent `model:` поведение при блокиран alias.
- **Код:** `ParseHookInput` / `RenderHookOutput` → `core.ToolCall`/`core.Verdict`; генератори: `.claude/settings.json` (permissions, hooks към `rr guard`, sandbox от `enforcement.sandbox`), `.claude/agents/*.md` с `model:` само от effective tiers (вход от fake resolver). `AGENTS.md` и `.agents/skills` не се генерират във вълна 1 (→ W3-D).
- **Acceptance:** golden за fixture-а (с `fakes.StrictPolicy()`); contract тест за формата на hook I/O срещу `claude` 2.1.316 (`RR_CONTRACT=1`); тест под `bwrap`: процес, който пише `riskrails.yaml`, получава EACCES. E2E „реален `claude -p` е отказан“ изисква W1-A+C+D → пуска го оркестраторът след merge (Gate 1).

### W1-E — адаптер **Codex** (hooks + config.toml + sandbox)
- **OWNS:** `internal/adapters/codex/**`, `cmd/rr/link_codex.go` (`import _`), `docs/research/verified/codex.md`; регистрира се с `runtimes.Register`
- **Research:** `codex --version`; формат на hooks (`permissionDecision: deny`, exit 2), покриване на MCP tools; `config.toml`: `sandbox_mode`, `[sandbox_workspace_write]`, `approval_policy`, `[agents]` (`default_subagent_model`, `max_concurrent_threads_per_session`); trusted project изискване; `--full-auto` статус; MCP в sandbox ([U] DES §14.7).
- **Код:** същият интерфейс като W1-D; генератори `.codex/config.toml`, `.codex/hooks.json` (`.agents/skills/` → W3-D).
- **Acceptance:** golden; contract тест с `codex exec --sandbox workspace-write` в temp repo (opt-in); `sync --check` зелен.

**Wiring след merge (оркестратор):** `wiring.GuardContext` ← реален policy resolver/loader/differ; `sync.InputProvider` ← реален resolver.

**Gate 1 (= P0 критериите от DES §13):** LOOSEN edit от агент отказан в тест; EACCES под sandbox; `rr sync --check` зелен за Claude + Codex в CI; `rr status` върху fixture-а. Review по §6.

---

## 4. Вълна 2 — P1 + P2 (6 агента паралелно, ~2 седмици)

P1 и P2 са независими след P0 (DES §13), затова вървят заедно.

### W2-A — `triage`: тегло, режими, rescore
- **OWNS:** `internal/triage/**`, `cmd/rr/cmd_triage.go`
- **Research:** `../claude-agentic/docs/weight.md` и `tests/test_weight.py::TestSQ1` — пренася 13-те случая като golden таблица (вход → оси → mode); известните непокрити случаи от `../claude-agentic/docs/known-risks.md`.
- **Код:** 6 оси (measured под, declared само вдига); scope по refs/hot_paths; reversibility/domain по пътища и съдържание (`irreversible_content`); novelty по manifest; coverage по `test_globs`; modes + `hard_floors` + `full_irreversible`; programme тригери; `Rescore(diff)` само нагоре; `--amend` преизчислява всичките шест; `policy_file_weight`.
- **Acceptance:** 13 SQ1 golden реда; property: rescore никога не сваля mode.

### W2-B — `models`: availability resolver
- **OWNS:** `internal/models/**`, `cmd/rr/cmd_models.go`
- **Research:** текущите docs на Anthropic `GET /v1/models` и errors, OpenAI `/v1/models`, OpenRouter; дали list е филтриран по ключ (DES [U]); точен текст на грешките на Claude Code при restricted model; `count_tokens` (само за записване, не се ползва).
- **Код:** алгоритъм от DES §4.2; probe с `max_tokens:1`, класификация по `error.type`; probe за абонаментни runtime-и (`claude -p … --model`), профил на инсталацията; кеш с TTL и refresh при 4xx; ladder, таблица §4.4, `never_downgrade_thinking`; `rr models probe|show`; предоставя `EffectiveTiers` на генераторите.
- **Acceptance:** `httptest` сървъри за всеки доставчик и всеки тип грешка; тест: нито един генериран манифест (W1-D/E golden с реален resolver) не съдържа модел ≠ PASS; липсващ BALANCED → `REFUSE {NO_TIER}`.

### W2-C — `verify` + `rr affected`
- **OWNS:** `internal/verify/**`, `cmd/rr/cmd_verify.go`, `cmd/rr/cmd_affected.go`
- **Research:** phpunit mapping по PSR-4 autoload от `composer.json`; `jest --findRelatedTests`, `vitest related`; pytest-testmon; `go list -deps -test` обратен граф.
- **Код:** адаптери phpunit, jest/vitest, pytest, go; `FullRunRequired` по `full_run_when`; `suite_budget`; `selection_misses` event; „двата факта“ за close.
- **Acceptance:** fixture-и за всеки екосистем с fake runner; реален тест за go адаптера върху самото repo.

### W2-D — `ledger` + `rr cost`
- **OWNS:** `internal/ledger/**`, `cmd/rr/cmd_cost.go`
- **Research:** реални транскрипти — Claude JSONL (`~/.claude-clean/projects/**`, само четене, без копиране на съдържание в repo-то; fixture-ите се синтезират), Codex sessions (`~/.codex/sessions`); usage полета вкл. cache read/write; актуални цени (DES §7.1 изходните цени са [U]).
- **Код:** `TranscriptParser` за Claude и Codex; агрегиране task/phase/tier/model; ценова таблица в данни, не в код; `rr cost --task`.
- **Acceptance:** синтетични fixture-и, които повтарят реалната структура; сумите съвпадат с ръчно изчислени.

### W2-E — `research`: роли, briefs, merge, cache
- **OWNS:** `internal/research/**`, `cmd/rr/cmd_research.go`, `templates/research/**`
- **Research:** Anthropic multi-agent post (4-те елемента на brief), `llms.txt` с версия, Context7 версия в заявката.
- **Код:** 6 роли от DES §5.2 с brief шаблони; брой по mode (§5.3); парсер на схемата §5.4; `merge` — dedup по source + Jaccard ≥ 0.8, без сливане при различна полярност/числа → `CONFLICT`; brief ≤ 3k токена; cache ключ `(sha, role, qhash)` в `~/.cache/riskrails/research/<repo-hash>/`, invalidation по READ; scout стартиране през `WorkerRunner` (fake).
- **Acceptance:** golden merge с умишлени дубликати и противоречия; invalidation тестове за всяка роля.

### W2-F — `plan` + `factory`
- **OWNS:** `internal/plan/**`, `internal/factory/**`, `cmd/rr/cmd_plan.go`
- **Research:** Claude Code `isolation: worktree` лимити (≤20, дълбочина 3), Codex `max_concurrent_threads_per_session`; Superpowers brief/report формат.
- **Код:** DAG (стъпки, файлове, тестове, after); `rr plan check` (пресичане ⇒ after, цикли ⇒ грешка); вълни; scope guard (въоръжава `guard` с файловете на стъпката); worker state machine със 4-те статуса; review loop с ескалация (рундове 1–2 / 3 tier нагоре / 4 човек); лимити; атомарен commit на стъпка; `WorkerRunner` имплементация за `claude -p` в worktree.
- **Acceptance:** table тестове за DAG; симулация на review loop с fake reviewer за всички клонове; `BLOCKED` спира вълната.

**Gate 2 (P1 + P2):** SQ1 зелени; манифест без FAIL модел; `selection_misses` се записва; симулирана full задача на fixture-а минава ≤5 скаута, brief ≤3k, два review етапа, cost в ledger.

---

## 5. Вълна 3 — P3, P4, P5 + MCP (6 агента паралелно, ~2 седмици)

P3 изисква P1 (готово след Gate 2); P4 и P5 са независими.

| Агент | OWNS | Research | Код | Acceptance |
|---|---|---|---|---|
| **W3-A autonomy + runner** | `internal/autonomy/**`, `cmd/rr/cmd_run.go` | `claude -p --permission-mode auto`, `codex exec -a never`, Docker sandbox mounts | L0–L4 семантика (DES §8.1); `ceiling.yaml` hash проверки преди всяка вълна; runner извън sandbox-а с local socket за hook-а; ask→deny компилация при L≥2 (подава флаг към генераторите); kill switch през `core.Hosting`; бюджети; draft PR изход | L2 run на light опашка срещу fake hosting завършва с draft PR; HALT спира ≤ 60 s (fake clock) |
| **W3-B GitHub** | `internal/hosting/github/**`, `internal/adapters/github/**`, `templates/github/**` | REST API за rulesets, reviews, team membership, contents; плановата наличност на file-pattern reviewers ([U] §14.1); дали App token може да approve-не | `core.Hosting`; генератори CODEOWNERS, ruleset JSON, CI workflows (`verify`, `policy check`); `rr sync --check --remote`; `rr policy check` с reviews API (code-owner човек ≠ автор; label и App review не се броят) | LOOSEN PR червен без валидно review; label от App не го прави зелен; тестове с записани (`go-vcr`) или ръчни fixture отговори |
| **W3-C release** | `internal/release/**`, `cmd/rr/cmd_release.go`, `templates/release/**` | npm trusted publishing, PyPI trusted publishing, Packagist webhook, GHCR с `GITHUB_TOKEN` | адаптери composer (първи), npm, pypi, docker: Detect/Preflight/DryRun/PrepareTag/CIWorkflow; `rr changelog --check` | golden CI workflows; никакви credentials в генерираните файлове (тест) |
| **W3-D MCP + skills + simplify** | `internal/mcp/**`, `skills/**`, `internal/simplify/**`, `cmd/rr/cmd_mcp.go` | `go-sdk` stdio API и текущата spec версия; Agent Skills формат в Claude/Codex; jscpd/ast-grep CLI | `rr mcp` с tools `triage`, `affected`, `research`, `status`; 5 тънки SKILL.md (rr-build, rr-ship, rr-release, rr-simplify, rr-status) + рендер за всеки runtime; `rr simplify` preflight | MCP contract тест с in-process клиент; skills golden |
| **W3-E Gemini + Cursor** | `internal/adapters/gemini/**`, `internal/adapters/cursor/**` | Gemini policy TOML, приоритети, BeforeTool, `.gemini/agents`; Cursor `hooks.json`, `failClosed`, 21 събития, `ask` не се налага | два `RuntimeAdapter` + генератори; `ask`→`deny` където runtime-ът не го налага | golden; документиран [U] списък |
| **W3-F degrade адаптери** | `internal/adapters/{kiro,copilot,opencode}/**`, `templates/precommit/**` | Kiro permissions.yaml, Copilot agent hooks, OpenCode config | AGENTS.md + pre-commit `rr guard --staged` + CI gates; `enforcement: ci_only` → таван L1 | runner отказва `ci_only` на L≥2 (тест) |

**Gate 3:** P3–P5 критериите от DES §13.

---

## 6. Review и интеграция

### 6.1 Review след всяка вълна (двустепенно, DES §6)
За всеки агент от вълната — свеж reviewer на Sonnet 5.5, паралелно:
1. **Spec compliance:** diff срещу brief + съответните DES секции + `OWNS` (писане извън = BLOCKER).
2. **Quality / adversarial:** за `guard`, `policy`, `autonomy`, `hosting` — фокус „как агентът може да заобиколи това“; за останалите — коректност и тестове.

BLOCKER/HIGH → една fix партида (същият агент през `SendMessage`, за да пази контекста). Рунд 3 → reviewer на Opus (един tier нагоре, DES §6); рунд 4 → собственикът.

### 6.2 Merge протокол на оркестратора
1. Всеки worktree branch `wave-N/<agent>` се rebase-ва върху `main` по реда на завършване.
2. `go mod tidy`, `go build ./...`, `go vet ./...`, `go test ./... -race`.
3. `CORE_CHANGE_REQUESTS` от report-ите се събират и прилагат **между** вълните като един commit.
4. `CONFLICTS` с DES се записват в `docs/design/errata.md` и в съответния ADR.
5. Tag `wave-N`.

### 6.3 Вълна 4 — Интеграция и end-to-end (1 агент + оркестратор, ~1 седмица)
- **W4-A wiring** (OWNS `cmd/rr/cmd_task.go`, `internal/flow/**`): `rr task start|amend|close` по потока от DES §2.3, свързва реалните имплементации на мястото на fakes; `rr handoff`, `rr recall`.
- **E2E тестове** върху `testdata/php-symfony`: light задача под Claude; guarded задача под Codex; LOOSEN опит; full_irreversible (миграция) → L0.
- **Финален adversarial review:** 2 паралелни reviewer-а — (1) enforcement/security по 4-те BLOCKER класа от DES §15; (2) consistency с DES и ADR-ите.

---

## 7. Обобщение на графика

| Вълна | Агенти (Sonnet 5.5) | Паралел | Зависи от | Оценка | Код [E] |
|---|---|---|---|---|---|
| 0 Bootstrap | оркестратор | — | — | 1 ден | ~0.6k |
| 1 P0 | W1-A…E | 5 | 0 | 1–1.5 седм. | ~2.7k |
| 2 P1+P2 | W2-A…F | 6 | 1 | 2 седм. | ~3.5k |
| 3 P3–P5+MCP | W3-A…F | 6 | 2 (W3-A); 1 (останалите) | 2 седм. | ~3k |
| 4 Integration | W4-A + 2 reviewer | 1–2 | 3 | 1 седм. | ~0.5k |
| Reviewers | по 1 на агент | до 6 | всяка вълна | — | — |

Общо ~10k реда Go за ~6–7 седмици календарно (срещу ~17 седмици серийно в DES §13), 17 implementer агента + ~20 reviewer-а.

**Токени [E]:** implementer ≈ 1.5–3M на агент (research + код + итерации по тестове), reviewer ≈ 150–300k. Общо в порядъка на 40–60M токена на Sonnet 5.5 за целия план; вълна 1 сама ≈ 10–15M. Ledger-ът (W2-D) измерва реалното от вълна 2 нататък и планът се преизчислява.

---

## 8. Шаблон на brief (един и същ за всеки агент)

```
Роля: implementer на модул <X> за RiskRails v4 (Go). Работиш в собствен git worktree.

ЦЕЛ: <1–2 изречения>
ПРОЧЕТИ ПЪРВО: AGENTS.md; docs/design/research-fable.md §<секции>; internal/core/*.go; docs/adr/<…>
ВЕЧЕ ИЗВЕСТНО (не проверявай отново): <фактите [V] от DES, които ползваш>
OWNS (пишеш само тук): <пътища>
НЕ ПИПАЙ: internal/core/**, go.mod, go.sum, cmd/rr/main.go, чужди internal/*
ИНТЕРФЕЙСИ: имплементираш <…>; ползваш <…> през fakes от internal/core/fakes

ФАЗА R (≤25%): провери <списък [U] твърдения и въпроси> в първоизточници.
  Запиши docs/research/verified/<X>.md в схемата FACTS/READ/GAPS/COST (DES §5.4), с URL.
  Факт, който опровергава DES → CONFLICT в report-а; не кодирай по опровергания вариант.
ФАЗА C+T: TDD. Атомарен commit на логическа стъпка (conventional commits).
  Нова зависимост или промяна в core → не я прави; опиши я в CORE_CHANGE_REQUESTS.

ПРАВИЛА ЗА КОД (AGENTS.md):
  - Не можеш да питаш: предположенията → ASSUMPTIONS; двусмислие, което мени дизайна → NEEDS_CONTEXT.
  - Минимум код за acceptance; без непоискани функции/настройки/абстракции; без обработка на невъзможни грешки.
    Интерфейсите в internal/core са нарочни — не ги заобикаляй и не ги „опростявай“.
  - Ако 200 реда могат да са 50 — пренапиши, преди да докладваш.
  - Fix рунд: само редовете, които находката изисква.

ACCEPTANCE: <тестовете от плана>; `make check` зелен.

REPORT (≤1.5k токена):
STATUS: DONE | DONE_WITH_CONCERNS | BLOCKED | NEEDS_CONTEXT
FILES / TESTS (команда + резултат) / ASSUMPTIONS / CONFLICTS / GAPS / CORE_CHANGE_REQUESTS
```

---

## 9. Рискове на самия план

| Риск | Мярка |
|---|---|
| Договорите от вълна 0 се оказват грешни → каскада от `CORE_CHANGE_REQUESTS` | вълна 0 се ревюира от един Opus reviewer преди вълна 1; прозорец за core промени между вълните |
| Research на агент опровергава DES (напр. Claude hook формат) | `CONFLICT` спира само засегнатата точка; оркестраторът решава и пише errata |
| Contract тестовете срещу живи `claude`/`codex` харчат токени и са нестабилни | opt-in с `RR_CONTRACT=1`, pinned версия в `docs/research/verified/*.md`, не в CI по подразбиране |
| Агент пише извън OWNS | spec-compliance review го хваща (BLOCKER); при merge `git diff --stat` се проверява срещу OWNS |
| Транскриптите на собственика съдържат чувствителни данни | W2-D само ги чете за структура; fixture-ите са синтетични; нищо реално не влиза в repo-то |
| Бюджет на токени | след всяка вълна `rr cost` (от вълна 2) или task notifications; решение на собственика преди следващата вълна |

---

## 10. Статус: вълна 1 затворена (2026-11-01, tag `wave-1`)

**Ревю:** рунд 1 (3× Sonnet: guard атака, policy/journal атака, spec compliance) → поправки; рунд 2 (2× Sonnet, нови) → поправки; рунд 3 (Opus) → SHIP_WITH_FIXES, BLOCKER поправен (`.git/**` + изолиран git), поправки за използваемост.

**Gate 1 (P0):**

| Критерий | Статус |
|---|---|
| LOOSEN edit от агент е отказан | ✅ тестове + e2e с бинара |
| sandbox: запис в `riskrails.yaml` ⇒ грешка | ✅ Codex (`codex sandbox`, EROFS/EACCES, RR_CONTRACT); ⚠️ Claude — sandbox-ът не стартира в тази среда, тестът е skip |
| `rr sync --check` зелен за Claude + Codex | ✅ локално върху fixture; ⏳ в CI на самото repo — вълна 4 (dogfooding) |
| `rr status` върху fixture | ✅ работи; ⏳ задачи се отварят от `rr task` — вълна 4 |
| PHP проект в light/guarded под реални Claude/Codex | ⏳ изисква triage + `rr task` (вълни 2 и 4) |

**Guard, всекидневна сесия L1 (106 извиквания):** allow 70% / ask 20% / deny 8% (преди поправките: 21/63/15). Корпус 827 случая, p99 186 µs.

**Пренесено към следващите вълни:** core: `ToolCall.Edits` (multi-file apply_patch), команда във `Verdict`/RenderHookOutput (вместо глобална променлива в Codex адаптера), `policy.DefaultRef`; W2-B: tiers в `wire.go`; W3-A: runner анкер за журнала и доверен SHA за InForce, проверка на Codex hook trust; известни граници: errata #6, #9, #12–#17.
