# Задача: архитектура и план за RiskRails v4, написан от нулата

## Твоята роля
Ти си водещият архитект (силен модел). Твоята работа е синтез, решения и проверка на чуждите изводи. **Събирането на информация не е твоя работа.** Ровенето в мрежа, документация и код делегирай на евтини паралелни подагенти (tier FAST: Haiku / най-евтиният модел на runtime-а, effort `low`). Сам четеш само техните структурирани резултати и малкото файлове, нужни за конкретно решение.

Пиши на **български**, техническите термини остават на английски.

## Контекст

### Какво е текущото (чернова, не легаси за пазене)
`/Store/ProjectToBuild/claude-agentic`, RiskRails 3.1: плъгин за Claude Code и Codex, около 31k реда Python/JS.
- Основни файлове: `state.py` е 5.4k реда (монолит). update/adopt/миграции са 4.4k. compact memory е 3.8k. Regex guard-овете са 2.4k, runtime-gate 1.3k.
- Hook манифестите са 4, ръчно поддържани. Има 10 alias команди и 63 отворени риска.
- Самата документация признава, че guard-овете са „tripwire, not a security boundary“, а одобрението може да се подправи през pty.
- Есенция, която се запазва:
  - измерен риск (измерването е долна граница, декларацията само вдига);
  - детерминистични gates;
  - „двата факта“ при затваряне: зелен verify + промени само в обхвата;
  - човешките gates се налагат от harness-а;
  - tiers вместо имена на модели;
  - append-only journal;
  - честен known-risks.

Нищо от кода не е задължително да оцелее. Може да се смени и технологията.

### Концепции, които новият проект трябва да покрие
1. **Модел рутер** според задачата (tiers FAST / BALANCED / STRONG / EXPERT).
2. **Agentic Factory** за паралелна работа на агенти: при имплементация **и при изграждане на спецификация и план** (виж т. 12).
3. **Триаж:** нужен ли е SDLC процес (light / guarded / full / programme) или директна промяна. Оценката се смята детерминистично и се преизчислява по реалния diff.
4. **Управление на риска според проекта.**
5. **По-малко токени**, основно чрез т. 1 и т. 2, но не само.
6. **Повече автономия на AI**, като човек задължително одобрява.
7. **Самостоятелна работа без човек**, когато рискът го позволява (нива L0–L4, изход само PR).
8. **Publish/release skills** според екосистемата на проекта (npm, PyPI, Composer/Packagist, Cargo, Go, Docker, Helm…): агентът подготвя, публикува CI през OIDC.
9. **Test/CI оптимизатор**, който избягва ненужните тестове (test impact analysis, задължителен пълен run при рискови промени).
10. **Simplify skill**, еквивалентен на `/simplify` в Claude Code, работещ и в Codex (и Gemini).
11. **Много доставчици:** Claude Code, Codex, Gemini CLI, Cursor, Kiro, Copilot, OpenCode, Meta/Llama през OpenCode/Goose + OpenRouter/LiteLLM.
12. **(Ново) Research factory за спецификация и план.** При събиране на информация се пускат паралелни евтини подагенти:
    - едни проверяват **кода**;
    - други **документацията на проекта** (README, ADR, docs/, specs);
    - трети **документацията на използваните технологии** точно във версиите от lockfile-овете;
    - четвърти търсят **вече съществуващи решения**: в repo-то (helpers, подобни модули), в инсталираните зависимости, в OSS и библиотеки.

    Броят и видът им зависи от тежестта на задачата. Резултатите се сливат от силен модел.

### Нови твърди изисквания (от собственика)
- **Всичко е на ниво проект.** В един версиониран файл в repo-то (напр. `riskrails.yaml`) са:
  - риск политиката;
  - **тежестите** на триажа (оси, прагове, критични пътища, твърди подове);
  - автономният таван;
  - **разрешените модели и tiers**.
- **Наличност на моделите:** effective tiers = (разрешени от проекта) ∩ (реално достъпни за акаунта/плана/runtime-а в момента). Пример: ако няма достъп до Fable, той **никога не се изисква и не се предлага**. Ескалацията и fallback-ът вървят само по наличните стъпала. Трябва механизъм за откриване на достъпа (probe, кеш, обновяване при грешка 4xx/квота) и ясно поведение, когато даден tier липсва (EXPERT → STRONG и т.н.).
- **Защита на самата политика:** понеже тя живее в repo-то, промяна, която **разхлабва** риска (по-висок автономен таван, по-ниски тежести, по-широк egress), трябва сама да минава като full/човешко одобрение (CODEOWNERS / required review). Агент не може да я одобри. Предложи механизма.

## Какво вече знаем (две вълни проучване, 18 Haiku агента)
Не ги проучвай отново. Използвай ги като отправна точка. Твърденията с [U] са непотвърдени и трябва да се проверят (виж Фаза 2).

**Пазарът (8 преки конкурента).**
- Нито един няма **изчислен** риск триаж или **политика, компилирана към нативни права/sandbox**. Тези два диференциатора трябва да се потвърдят или опровергаят.
- AWS AI-DLC v2.11:
  - TS engine, компилиран с Bun до бинар, 11 профила, 131 audit събития;
  - audit-first запис, PreToolUse гард „няма dev без одобрен план“, HUMAN_TURN преди одобрение;
  - профилът се избира от LLM, одобрението е по присъствие без идентичност, Guard Policy е `off` по подразбиране.
- Superpowers (~310k★):
  - свеж implementer на задача, review в два етапа (spec → quality);
  - статуси DONE / DONE_WITH_CONCERNS / BLOCKED / NEEDS_CONTEXT, ескалация на модела след 3 рунда;
  - worktree preflight, евтин inline вариант;
  - всичко е prompt-only, implementer-ите са **серийни**.
- GSD Core: вълни от свежи subagents, pause/resume, атомарен commit на задача, plan-review convergence, `model_profile` + `model_overrides`; autonomous режим без риск gate.
- OpenSpec: delta specs ADDED/MODIFIED/REMOVED → archive. В Uvik benchmark е най-евтиният spec процес (28% токени; 42/50 merged срещу 36/50 без spec; $2.71 срещу $2.43 на тикет) [единичен vendor benchmark].
- Spec Kit v1.0: 38 integrations + generic fallback, extensions с before/after hooks, отделни bugfix/assess входове; тежък.
- Addy agent-skills: 25 skills, SKILL.md като източник, prompt-only gates.
- BMAD: 4 пътя по преценка, `custom/` слой, unattended epic loop; token exhaustion в case study.
- Kiro/Cursor:
  - Cursor има 21 hook събития, deny/ask/allow, `updated_input`, `failClosed`, нива enterprise→team→project→user;
  - **Cursor зарежда Claude-style hooks**;
  - Kiro има permissions.yaml deny>ask>allow, а workspace правата пази извън repo-то.

**Механизми по концепция.**
- Рутинг: детерминистична таблица > ML (LLMRouterBench 2026: много рутери не бият baseline). Strong планира, cheap изпълнява (Aider). Ескалация по сигнали с таван. Смяна на модела на главната сесия чупи prompt cache.
- Factory:
  - worktree/контейнер на работник;
  - DAG по **файлова собственост**;
  - изричен лимит на конкурентност и turns;
  - structured results ≤1–2k токена;
  - паралелно писане само при непресичащи се файлове;
  - Claude: `isolation: worktree`, ≤20 конкурентни, дълбочина 3. Codex: `max_concurrent_threads_per_session`.
- Триаж: AI-DLC адаптивен, BMAD/Kiro/Spec Kit ръчни. Никой няма ескалация по средата на задачата. Spec фазата е 28–44% от токените и не помага при bugfix/refactor.
- Enforcement:
  - Codex има Seatbelt/Landlock+seccomp;
  - Claude има permissions deny→ask→allow + sandbox (bubblewrap/Seatbelt) с `failIfUnavailable`; Read/Edit не са в sandbox-а;
  - Gemini има TOML policy engine;
  - Docker Sandboxes (microVM) поддържа всички CLI-та;
  - заплахата: lethal trifecta (Willison);
  - shell командите се парсват като AST (`mvdan/sh`), не с regex.
- Автономия: Claude има режими default/acceptEdits/plan/auto/dontAsk/bypass, а auto пада на prompt след 3/20 блока. `codex exec` е read-only по подразбиране. Copilot работи с draft PR. Renovate прави automerge след soak. Anthropic: auto-approve расте с опита.
- Release: прави се dry-run и preflight, публикува CI през OIDC trusted publishing (npm, PyPI, NuGet). Агентът не държи credentials. Маven/Terraform/mobile имат слаб dry-run.
- Test impact:
  - Datadog TIA (coverage), pytest-testmon, jest `--findRelatedTests`, phpunit-tia / Pest TIA, Nx/Turbo/Bazel;
  - пълен run при lockfile, config, CI, миграции, непокрит файл или висок риск;
  - nightly full run;
  - метрика „selection misses“.
- Токени:
  - prompt caching (четене 0.05–0.1×);
  - малък always-loaded файл;
  - progressive disclosure на skills;
  - subagent summaries;
  - JIT retrieval;
  - repo map/LSP (Serena);
  - детерминистични инструменти първо;
  - cost ledger.
- Преносимост: AGENTS.md (Linux Foundation) + Agent Skills (`.agents/skills`) + MCP като преносим слой + тънки hook адаптери. Без hooks (Aider, Goose) защитата отива в pre-commit/CI. Манифестите се генерират с `--check`.

**Текущо предложение (за преоценка, не за приемане наготово).**
- Един статичен бинар на Go (`rr`): triage, router, plan/DAG, factory, verify/affected, autonomy, release, ledger, policy compiler, shell AST guard, journal (JSONL, audit-first).
- Повърхности: CLI, MCP сървър, hook адаптери, генератори на runtime конфигурации, GitHub rulesets и CI workflows.
- Одобрение server-side (required review / подписано). Позиция: risk engine + enforcement, съвместим с методологии (OpenSpec за specs, Superpowers-style протокол за implementer/review), а не нова методология.
- Цел: 6–9k реда.

## Как да работиш

### Правила за подагентите (задължителни)
- Изследователските подагенти са на **най-евтиния tier** (Claude Code: `model: haiku`, Codex: `default_subagent_model` = най-евтиния, Gemini: Flash), с effort `low`, само четене, без писане на файлове.
- Пускай ги **паралелно в една стъпка**, най-много 10 едновременно. Всеки получава тясна тема, вече известното (за да не го повтаря) и **схема на отговора**:

  ```
  FACTS: - <твърдение> | <източник URL или file:line> | [V]/[U]
  STEAL: - <механизъм> → <номер на концепция>
  AVOID: - <антипатерн>
  GAPS:  - <какво не успя да провери>
  ```

  Отговорът е под 500 думи, без проза извън схемата.
- Силен модел (BALANCED/STRONG) ползвай само за: (а) твоя синтез, (б) **един** adversarial review агент накрая. Никога флот от силни модели. Повторни опити на евтин модел за мисловна задача са забранени.
- Ако даден модел/tier не е достъпен в твоя акаунт, не го изисквай. Ползвай следващото налично стъпало и го отбележи.

### Фаза 0: минимален локален контекст (ти, ≤10 tool calls)
Прочети само: `claude-agentic/README.md` (до „The guards“), `ROADMAP.md`, `docs/known-risks.md` (заглавията), `docs/weight.md`, един `profiles/*.json`. Не чети `state.py`, `update.py`, `adopt.py` и логове.

### Фаза 1: паралелно събиране (FAST, една вълна, ~9 агента)
1. **Model availability**: как всеки runtime (Claude Code, Codex, Gemini, Cursor, OpenCode) разкрива кои модели са достъпни за акаунта/плана (настройки, `/model`, API list models, грешки при недостъпен модел, квоти). Как да се направи евтин probe и кеш.
2. **Per-project config precedence**: как Claude, Codex, Gemini, Cursor и Kiro сливат project/user/enterprise настройки. Какво може да се наложи от repo-то и какво не. Как CODEOWNERS / rulesets защитават конфигурационен файл.
3. **Research-factory патерни**: как съществуващи системи паралелизират изследването преди spec/plan. Claude Code `Explore`/Plan subagents, Codex subagents, GSD research фаза, BMAD analyst, OpenHands, Anthropic multi-agent research system (orchestrator-worker, цифри за токени), Google/OpenAI deep research.
4. **Version-pinned tech docs**: инструменти за документация на точната версия на зависимост. Context7 MCP, DeepWiki, devdocs, llms.txt, официални docs по версия, четене от `vendor/`/`node_modules`. Как се извличат версиите от lockfile-ове (composer.lock, package-lock, uv.lock, go.sum, Cargo.lock).
5. **Prior-art / reuse search**: как се откриват вече съществуващи решения. В repo-то (ripgrep, ast-grep, symbol index, Serena/LSP, дублиране с jscpd). Сред инсталираните зависимости. В OSS (GitHub code search, Sourcegraph, пакетни регистри, awesome-листи). Как се оценява годност (лиценз, поддръжка, сигурност).
6. **Token economics на multi-agent**: публикувани цифри за разхода на subagent fan-out спрямо единичен агент (Anthropic multi-agent research ~15× токени [U]). Prompt caching при subagents. Batch API отстъпки за неинтерактивна работа. Кеширане на резултатите от изследване по commit SHA. Дедупликация между агенти.
7. **Проверка на [U] твърденията, част A**: AI-DLC (дали `aidlc-plan-approval-guard`, HUMAN_TURN и tier projection са както са описани); Cursor (зарежда ли Claude-style hooks; `failClosed`; работят ли hooks headless).
8. **Проверка на [U] твърденията, част B**: Codex hooks (кои събития, може ли deny; покрива ли sandbox-ът MCP); Gemini CLI (hooks в extensions, policy engine tiers, Agent Skills поддръжка).
9. **Езикът на ядрото**: hook latency и разпространение. Go статичен бинар срещу Bun-compiled TS срещу Rust. Startup времена, размер, cross-compile, npm optionalDependencies патерн (esbuild/biome), MCP SDK зрялост.

### Фаза 2: втора, тясна вълна (FAST, само при нужда, ≤4 агента)
Само за противоречия или GAPS от Фаза 1, които влияят на решение. Всеки агент проверява **една** конкретна претенция в първоизточник.

### Фаза 3: синтез (ти)
Вземи решенията и ги обоснови с FACTS от агентите (цитирай източника). Където данни няма, кажи го и дай препоръка, не изброяване на варианти.

### Фаза 4: adversarial review (един агент, BALANCED или STRONG)
Подай му само готовия документ. Задачата му: да търси противоречия, неизмерими твърдения, начини агент да заобиколи защитите (включително през project policy файла), скрити разходи за токени. Поправи BLOCKER/HIGH находките с една партида.

## Какво да предадеш

Един документ (`/Store/ProjectToBuild/agentic-risk-rails/docs/design/riskrails-v4.md`, ако имаш право да пишеш там, иначе в отговора) със следните секции:

1. **Позициониране:** диференциаторите и какво съзнателно НЕ правим (оставяме на OpenSpec, Superpowers, Addy…).
2. **Архитектура:** компоненти, повърхности (CLI / MCP / hooks / генератори), поток на една задача от триаж до затваряне, диаграма.
3. **`riskrails.yaml`:** пълна схема с коментиран пример за PHP/Symfony проект. Секции:
   - `risk` (оси, тежести, прагове, критични пътища, твърди подове);
   - `models` (разрешени tiers, модел по runtime, fallback ladder, бюджети);
   - `autonomy` (таван L0–L4, kill switch);
   - `enforcement` (protected paths, egress, команди);
   - `verify` (тест адаптери, правила за пълен run);
   - `release` (екосистема, канал);
   - `research` (scouts по ниво).

   Плюс правилата за precedence (project / user / enterprise) и защитата при разхлабване.
4. **Model availability resolver:** алгоритъм (probe → кеш → effective = allowed ∩ available → ladder), поведение при липсващ tier, поведение при грешка по време на работа. Гаранция, че недостъпен модел никога не се иска.
5. **Research factory за spec/plan:**
   - роли (code-scout, project-docs-scout, tech-docs-scout по версия, prior-art-scout, risk/history-scout, test-scout);
   - колко и кои се пускат на всяко ниво;
   - схема на изхода, дедупликация, кеш по commit SHA;
   - как силният модел ги слива;
   - бюджет в токени на ниво.
6. **Implementation factory:** DAG, файлова собственост, вълни, worktree/контейнер, двустепенно review, статуси, ескалация, лимити.
7. **Токен модел:** таблица на очаквания разход по ниво (light / guarded / full / programme) и по фаза. Топ 10 мерки за намаляване с очакван ефект и как се измерва (ledger).
8. **Автономия и одобрение:** L0–L4 срещу риска, unattended runner, server-side одобрение, kill switch, audit.
9. **Модули 8–10:** release адаптери, test impact, simplify. Интерфейс и първите адаптери.
10. **Мулти-доставчик:** матрица runtime → какво се налага нативно / какво е gap / degrade режим.
11. **Технология:** решение за езика с цифри, разпространение, структура на repo-то.
12. **ADR-и:** по едно кратко за всяко ключово решение (контекст, решение, отхвърлени варианти, последствия).
13. **План по фази:** P0…P5, всяка с обхват, критерий за готовност и оценка на размера.
14. **Рискове и отворени въпроси**, само тези, които собственикът трябва да реши.

## Граници
- Не променяй `/Store/ProjectToBuild/claude-agentic`. Само чети.
- Без commit, push, publish, инсталиране на пакети.
- Обща цел за разход: Фаза 1–2 на евтиния tier. Силният модел не чете суров уеб или цели файлове над ~500 реда.
- Накрая докладвай: колко агента на кой tier си пуснал, грубо колко токена, кои [U] твърдения си потвърдил или опровергал.
