# RiskRails от нулата: проучване и предложение за чист редизайн

Дата: 2026-10-31. Отправна точка: `/Store/ProjectToBuild/claude-agentic` (RiskRails 3.1.0), прието за чернова.
Метод: 10 паралелни Haiku агента. Девет проучиха конкурентите в мрежата, един направи вътрешен анализ.
Агентите са работили основно по откъси от търсения. Проверени са само първичните източници за:
- правата и sandbox на Claude Code;
- sandbox на Codex;
- prompt caching;
- Datadog TIA;
- Anthropic „measuring agent autonomy“.

Вендорските цифри за спестявания не са проверени, затова не им се доверявай без собствено измерване.

## 1. Какво е текущото и какво струва

| Подсистема | Размер | Оценка |
|---|---|---|
| `state.py` (монолит: lifecycle, journal, budgets, batch) | 5 387 реда, 245 функции | разбий на модули |
| `update.py` + `adopt.py` + 11 миграции | ~4 400 реда | премахни; v1 схема, без миграции |
| compact memory (`memory_sync/compact/store/format`) | ~3 800 реда | замени с journal + recall от git |
| `runtime-gate.py` (квоти, outage) | 1 312 | опрости до бюджет в router-а |
| `guard/paths.py` + `ere.py` + `git.py` (regex) | ~2 400 | замени с shell AST + native sandbox |
| `context-guard.py` | 831 | запази идеята, малък код |
| installer `riskrails.js` + setup + merge-codex | ~2 400 | генератор от един манифест |
| 10 alias skills, 4 hook манифеста (2 Claude + 2 Codex) | — | махни / генерирай |

Общо: ~31k реда Python/JS, 59 тестови сюита, 63 отворени риска. Самата документация признава, че guard-овете са „tripwire, not a security boundary“, а човешкото одобрение може да се подправи през pty.

**Есенция, която се запазва:** измерен риск (измерването е долна граница, декларацията може само да вдигне), детерминистични gates без мнение на модел, „двата факта“ при затваряне, човешки gates, наложени от harness-а, а не от prompt, tiers вместо имена на модели, append-only journal, честен known-risks.

## 2. Какво правят доказаните проекти (по концепции)

### 1. Модел рутер
- RouteLLM: 95% от качеството на GPT-4 при 14–26% повиквания към него. FrugalGPT е каскада. Cursor Router: Compass complexity score и eligibility при 75% one-sided confidence. LiteLLM е само reliability plumbing. Aider: strong architect + cheap editor.
- LLMRouterBench (2026): много рутери, включително комерсиални, не бият надеждно прост baseline.
- **Извод:** детерминистична таблица задача×риск→tier. Ескалацията е по сигнали (червени тестове ×2, повтарящи се tool грешки, findings от review) и е с таван. Strong планира, cheap изпълнява. Рутинг само на ниво subagent, без смяна на модела на главната сесия, за да не се чупи prompt cache. Логвай всяко решение и прави shadow-eval по-късно от journal-а.

### 2. Agentic Factory
- Claude subagents: `isolation: worktree`, до 20 конкурентни, дълбочина 3, `maxTurns`. Codex: `max_concurrent_threads_per_session`, изрично предупреждение за конфликти при паралелно писане. Conductor и Vibe Kanban: worktree + branch + PR на работник. Sculptor и container-use: контейнер на агент. Uzi: checkpoint/rebase.
- **Извод:** DAG от плана със **собственост върху файловете**. Worktree на работник (контейнер при unattended) и изричен лимит на конкурентност и turns. Евтини работници, силен merger/reviewer. Резултатите се връщат по JSON схема (≤1–2k токена). Конфликт при merge сериализира задачата, без merge от модел „на сляпо“.

### 3. SDLC или директна промяна
- Spec Kit е фиксиран и тежък („overkill“ по Fowler). В Kiro режимът (vibe/spec) се избира ръчно. AWS AI-DLC е адаптивен (условни стъпки). BMAD има три scale tracks.
- Uvik benchmark: spec фазата изяжда 35% от токените и не помага при bugfix и refactor. Никой от тях няма чиста **ескалация по средата на задачата**, а това е пазарна дупка.
- **Извод:** три нива. Light не създава артефакти, само commit и verify. Сигналите са евтини и детерминистични: размер на diff, пътища, glob-ове за критичен домейн, покритие на засегнатите файлове, публичен API/схема/миграция. Категорията е твърд под (по ITIL). Повторна оценка се прави по реалния diff, а ескалацията добавя по една стъпка, не рестартира процеса. Причините се показват винаги.

### 4. Управление на риска според проекта
- Codex: OS sandbox (Seatbelt/Landlock+seccomp) + approval_policy. Claude: permissions deny→ask→allow и sandbox (bubblewrap/Seatbelt, egress proxy) с `failIfUnavailable`. Gemini: TOML policy engine (toolName, argsPattern, decision, priority).
- Docker Sandboxes (microVM) поддържа Claude, Codex, Gemini и Copilot. Cedar/OPA са policy-as-code. Simon Willison описва „lethal trifecta“ като модел на заплахата.
- **Извод:** един декларативен `riskrails.yaml` на проект, компилиран към нативните механизми на всеки runtime. Компилаторът докладва като „gap“ всеки контрол, който runtime-ът не може да изрази. Слоеве:
  - VM/контейнер;
  - native sandbox, fail-closed;
  - egress allowlist;
  - tool policy, а hook-ът парсва shell **AST**, не regex;
  - trifecta флаг: след прочетено недоверено съдържание външните sinks искат одобрение;
  - server-side защити (branch protection, push protection, required checks);
  - journal.

### 5. Токени
Подредено по спестяване спрямо усилие:
1. Prompt caching и cache-friendly подредба. Четенето от кеш струва 0.1× (0.05× за Opus/Sonnet 5.5), а смяна на tool дефинициите го инвалидира.
2. Минимален always-loaded файл (рутер ≤30 реда).
3. Progressive disclosure на skills.
4. Subagent изолация със summary.
5. Изчистване и compaction на стари tool резултати.
6. JIT retrieval: пътища и заявки, не цели файлове.
7. Repo map / LSP навигация (Serena).
8. Детерминистични инструменти преди модела (affected tests, ripgrep).
9. Лимити за output.
10. Вграден cost ledger (тип ccusage) за измерване преди и след.

### 6–7. Автономия: човек одобрява, или напълно сам при нисък риск
- Claude: режими default/acceptEdits/plan/auto/dontAsk/bypass. Auto пада обратно на prompt след 3 последователни или 20 общо блокирания. Codex `exec` е read-only по подразбиране. Copilot agent работи само чрез draft PR и човешко review. OpenHands има `MAX_ITER`. Renovate прави automerge само след soak и зелен CI.
- Anthropic (2026): auto-approve расте с опита (20%→40%+). Препоръката е евтино прекъсване, не одобрение на всяко действие.
- **Извод:** нива L0–L4:

| Ниво | Поведение | Кога |
|---|---|---|
| L0 Observe | само четене / plan | винаги разрешено |
| L1 Propose | всяко писане и shell искат човек | критичен домейн |
| L2 Supervised | edits свободно, shell/network питат, изход = branch | нормален риск |
| L3 Unattended-PR | headless + allowlist + контейнер, CI задължителен, бюджет/време, изход **само PR**, човек мърджва | нисък риск |
| L4 Unattended-merge | automerge само за тесни класове (deps patch, docs) след soak | изрично в политиката |

Ефективното ниво е `min(таван на проекта, ниво по риска на задачата)`. Агентът не може да вдигне тавана. Kill switch е label/файл. Одобрението се пази **server-side** (GitHub required review / signed approval), не с pty проверка. Само така не може да се подправи от локален процес.

### 8. Publish/release skills
Адаптер на екосистема, избран по manifest:

| Екосистема | Detect | Инструмент | Auth | Dry-run | Необратимо |
|---|---|---|---|---|---|
| npm | package.json | Changesets / semantic-release | OIDC trusted publishing | `npm publish --dry-run` | publish на версия |
| Python | pyproject.toml | uv / release-please | PyPI trusted publishing | `uv build` + `twine check` | upload |
| PHP | composer.json | git tag + Packagist webhook | tag push | `composer validate --strict` | tag push |
| Rust | Cargo.toml | release-plz / cargo-release | token | `cargo publish --dry-run` | publish |
| Go | go.mod | GoReleaser | tag + GH token | `--snapshot` | tag push |
| Docker | Dockerfile | buildx + cosign keyless | OIDC | build без `--push` | push |
| Helm | Chart.yaml | chart-releaser | GH token | `helm lint/package` | release |
| NuGet / Maven / mobile | csproj / pom / Fastfile | … | … | слаб dry-run → staging gate | … |

Агентът само подготвя: версия, changelog, build, проверка на пакета, release-plan. Самото публикуване става **в CI с OIDC** и агентът не държи credentials. Необратимата стъпка е на човек или на изрична политика.

### 9. Test/CI оптимизатор
- Datadog TIA е coverage-based: пропуска тест само ако покритите файлове са идентични. Meta PTS и Gradle PTS са ML и изискват история. Bazel rdeps, Nx affected и Turbo `--affected` са статичен граф. pytest-testmon, jest `--findRelatedTests` и PHP phpunit-tia / Pest TIA работят по подобен принцип.
- **Извод:** интерфейс `rr affected <diff> → {tests, reason, confidence}` с адаптер на екосистема, без ML в началото. **Пълен run** се пуска при промяна на lockfile/manifest, CI/build config, миграции/схема, нов или непокрит файл, висок риск или остарял baseline. CI получава матрица от селектора, а dorny/paths-filter остава само като pre-gate. Пълен run се прави nightly и post-merge. Изпуснатите тестове (selection misses) се записват като метрика за безопасност. Flaky тестовете отиват в карантина, но винаги се пускат.

### 10. Simplify за Claude и Codex
Един SKILL.md (Agent Skills стандарт) с тънки обвивки (Claude skill, Codex `.agents/skills`, Gemini TOML command). Обхватът е **само diff-ът**. Първо работят детерминистичните детектори (jscpd, knip, ruff, Rector, PHPStan, ast-grep), моделът само преценява и прилага. Тестове преди и след, без нови suppressions. Една партида, само качество, бъгове не се търсят.

### 11. Много доставчици
- AGENTS.md е стандарт под Linux Foundation, а Agent Skills (`.agents/skills`) се четат от Codex, Gemini, Copilot и Cursor. Hooks има в Claude, Codex, Gemini, Cursor, Copilot и OpenCode (като plugin). Goose, Aider и Crush нямат hooks.
- **Извод:**
  - core engine + MCP server като преносим слой;
  - тънки hook адаптери, които нормализират payload и викат същия бинар;
  - generated manifests с `--check` в CI;
  - degrade към git pre-commit/CI, където hooks липсват;
  - Meta/Llama и други модели през OpenCode/Goose + OpenRouter/LiteLLM, с tier→model профили.

## 3. Предложена архитектура

```
riskrails.yaml (на проект)          profiles/ (tier → модел за всеки runtime/план)
        │                                    │
        ▼                                    ▼
┌──────────────────────── rr (един статичен бинар, Go) ─────────────────────────┐
│ triage  router  plan/DAG  factory  verify/affected  autonomy  release  ledger │
│ policy compiler ── shell AST parser ── journal (JSONL, event-sourced)         │
└──────┬──────────────┬─────────────────┬───────────────────┬───────────────────┘
       │ CLI          │ MCP server      │ hook adapters     │ generators
       ▼              ▼                 ▼                   ▼
   човек/CI      всеки runtime    claude/codex/gemini/  CLAUDE.md→@AGENTS.md,
                 (tools)          cursor/copilot/       settings/config.toml/
                                  opencode              policy.toml, GH rulesets,
                                                        CI workflows
skills/*.md (Agent Skills): build, ship, release, simplify, status — тънки, викат `rr`
```

**Технология: Go**
- Hook-ът се изпълнява при всяко tool повикване. Бинарът стартира за ~2–5 ms, срещу ~40–80 ms за python/node.
- Без runtime зависимости, лесен cross-compile, официален MCP Go SDK.
- `mvdan/sh` дава истински bash AST вместо regex. CEL (cel-go) служи за изрази в политиката, по-лек от OPA.
- Разпространение като esbuild/biome: npm пакет с бинари за всяка платформа + Homebrew + `go install`.
- Алтернатива е Rust, с по-бавна итерация. TypeScript е по-лош избор заради startup на hook-а.

**Състояние:** `.ai/journal.jsonl` (append-only, в git) + производно `.ai/.local/state.json`. Без migrations framework до v2. Recall е `rr recall <paths>` върху journal + `git log`, не отделна memory подсистема.

**Цел за размер:** ~6–9k реда Go срещу 31k днес.

## 4. Какво се маха от легасито
- 10 alias skills и 4 ръчни hook манифеста; генерират се.
- Migrations/update/adopt (~4.4k реда). Adopt може да се върне по-късно като отделен инструмент.
- Compact memory (~3.8k реда).
- Regex guard-ове като основна защита; остават като допълнителен слой върху AST.
- pty-базирано одобрение; заменя се със server-side review.
- Квотният runtime-gate като отделна подсистема; влиза в router-а като бюджет.
- `current.json` fallback-ове и дублираните инструкции за Claude/Codex.

## 5. Етапи
1. **P0 Core:** `rr` бинар, `riskrails.yaml` схема, journal, policy compiler, hook адаптери за Claude и Codex, AST guard, `rr status`.
2. **P1 Triage + router + verify:** скала, tiers/профили, ескалация, `rr affected` (pytest, jest/vitest, phpunit/pest, go), cost ledger.
3. **P2 Factory:** DAG с файлова собственост, worktree на работник, конкурентност, structured results, merge/serialize.
4. **P3 Autonomy L0–L4:** headless runner (`claude -p`, `codex exec`, `gemini -p`) в контейнер, PR-only, kill switch, бюджети, server-side approval.
5. **P4 Skills:** release адаптери (npm, PyPI, Composer, Docker, Helm, Go) + генерирани CI workflows; simplify.
6. **P5 Още runtimes:** Gemini, Cursor, Copilot, OpenCode; degrade режим за Aider и Goose.

## 6. Отворени решения
1. Езикът на core-а: Go (препоръка), Rust или TypeScript.
2. Остава ли правилото „пълен suite при затваряне“, или verify scope зависи от риска (light = само засегнатите тестове)?
3. Одобрение: само server-side (GitHub review), или локален диалог като опция за малки задачи?
4. Име и пакет: ново repo (`agentic-risk-rails`) без обратна съвместимост?

---

## 7. Втора вълна: преки конкуренти (8 Haiku агента, 2026-10-31)

| Инструмент | Какво е реално | Наложено с код | Само prompt дисциплина | Вземаме | Избягваме |
|---|---|---|---|---|---|
| **AWS AI-DLC** v2.11 | TS engine (~60 модула, Bun → бинар `aidlc`), 11 профила, 131 audit събития | state machine, audit-first запис, PreToolUse гард „няма dev без одобрен план“, HUMAN_TURN преди одобрение | избор на профил (LLM предлага, човек потвърждава), съдържание | audit-first атомарност; регистър на събитията + тест за задължителните; tier, записан веднъж и проектиран във всеки harness; гард за одобрен план | профил по преценка, а не по риск; одобрение по присъствие, без идентичност; Guard Policy `off` по подразбиране; 60 модула още в старта |
| **Superpowers** (310k★) | skills + един SessionStart hook | само инжектиране на bootstrap skill (JSON shim по runtime), `git check-ignore`, worktree | review ред, round caps, избор на модел, „1% правило“ | свеж implementer на задача с brief/report файлове; статуси DONE / DONE_WITH_CONCERNS / BLOCKED / NEEDS_CONTEXT; **двустепенно review** (spec → quality); по-силен модел след 3 неуспешни рунда; worktree preflight с baseline тестове; евтин inline вариант с един финален review | всичко само в prompt; без триаж; **implementer-ите са серийни** (паралел при писане = конфликти) |
| **GSD Core** (наследник на archived get-shit-done) | Node installer, `.planning/` артефакти, вълни | малко; основно оркестрация | вълни, verify, autonomous | pause/resume handoff; атомарен commit на задача (undo/bisect); plan-review convergence loop; `model_profile` + `model_overrides`; forensics на провален run; план ≈ 2–3 задачи | `/gsd-autonomous` без риск gate; скъпи per-task subagents без измерване |
| **OpenSpec** (73k★) | Node CLI, `specs/` + `changes/` + `archive/` | `validate`, archive (без TTY изисква `--yes`) | всичко останало | **delta specs ADDED/MODIFIED/REMOVED → merge при archive** като формат за изискванията във full режим; `skip_specs` като light ключ; една команда, рендерирана за 30+ tools | archive като единствено одобрение; телеметрия по подразбиране |
| **Spec Kit** v1.0 (144k★) | Python CLI, 38 integrations + `generic` | gates само чрез workflow/extension | spec/plan/checklist | integration adapter на агент + generic fallback; extensions с before/after hooks; overlays без fork; отделни входове за bugfix и assess | церемония за всяка промяна; shell стъпки без sandbox; разрастване на артефакти |
| **Addy agent-skills** (112k★) | 25 skills + 9 команди, широки практики | почти нищо (session-start/cache hooks) | всички gates | SKILL.md като източник + тънки install адаптери; router skill; progressive disclosure; `simplify-ignore` маркер; таблици „рационализации“, но **подкрепени с детерминистична проверка** | ръчно дублирани команди за всеки runtime; skills без tool scoping; неизмерена ефективност |
| **BMAD** v6.12 / V7 alpha | skills + `_bmad/` + модули (Loop, Test Architect) | нищо значимо | всичко, включително избор на път | речник от 4 пътя (trivial / one session / epic / project); `custom/` слой, който оцелява при update; инсталация през open Skills CLI; unattended epic loop с човешки gate накрая | избор по преценка; персони по подразбиране (token exhaustion в case study); нестабилни имена |
| **Kiro / Cursor** | IDE + CLI с истински hooks и permissions | Cursor: 21 събития, deny/ask/allow, `updated_input`, `failClosed`, enterprise→team→project→user; Kiro: PreToolUse block, permissions.yaml deny>ask>allow, admin `managed-settings` | Cursor `ask` в preToolUse не се налага | Cursor **зарежда Claude-style hooks (exit 2)**, затова адаптерът е почти безплатен; `failClosed`; слоеве deny>ask>allow; **Kiro пази workspace правата извън repo-то** | fail-open по подразбиране; cloud агентите на Cursor не пускат MCP/user hooks; Kiro схемата се мени между версии |

### Изводи, които променят предложението

1. **Нишата е потвърдена.** Нито един от 8-те няма (а) **изчислен** риск триаж или (б) риск политика, **компилирана** към нативен sandbox и права. Всички избират процеса по преценка (LLM или човек), а повечето налагат само чрез prompt. Това са двата диференциатора. Всичко останало (методология, skills, specs) вече е решено от други.
2. **Позиция: risk engine + enforcement, не поредната методология.** Направи RiskRails съвместим с методологиите вместо да ги преписваш:
   - spec форматът във full режим = OpenSpec delta specs (най-евтиният spec flow: 28% токени, 42/50 merged срещу 36/50 без spec);
   - implementer/review протоколът = по модела на Superpowers, но наложен от engine-а;
   - практическите skills (API, UI, perf, security) могат да идват от Addy/Superpowers, а RiskRails решава кога и с какъв риск.
   Ядрото става по-малко.
3. **Agent factory:** паралелно писане само при доказано **непресичащи се файлове**. Останалото е серийно (Superpowers го прави винаги серийно, Codex предупреждава за конфликти). Вълни като GSD, преди всяка вълна engine проверява файловата собственост, атомарен commit на задача.
4. **Review:** двустепенно (spec compliance → quality), статусни кодове от implementer-а, по-силен модел след N рунда. Всичко това се брои и лимитира от engine-а, не от prompt.
5. **Одобрение:** AI-DLC потвърждава слабостта на „присъствие без идентичност“. Остава препоръката за server-side review или подписано одобрение. HUMAN_TURN проверката става допълнителен локален слой.
6. **Политика по слоеве:** `riskrails.yaml` в repo-то **може само да затяга**. Разхлабване (по-висок autonomy таван, по-широк egress) се прави само в user/admin scope извън repo-то, по модела на Kiro и Cursor. Иначе клонирано repo може да си даде L4.
7. **Journal:** audit-first (събитието се записва преди промяната на state) + регистър на събитията с тест. Вместо compact memory: OpenSpec-style archive за изискванията + journal за изпълнението.
8. **Нива на процеса:** light / guarded / full + **programme** (многосесийна, epic, по BMAD) вместо отделна команда build-all.
9. **Адаптери:** Cursor и Kiro имат достатъчно hooks. Cursor чете Claude-format hooks, така че един адаптер покрива и двата. За всеки адаптер `failClosed: true`, за всяка pinned версия contract тестове.
10. **Технология:** AI-DLC доказва, че и TypeScript, компилиран до бинар (Bun), работи. Go остава препоръката: по-малък бинар, по-бърз старт, `mvdan/sh`. Ако екипът е по-бърз на TS, Bun compile е легитимна алтернатива.
