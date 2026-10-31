# Errata към research-fable.md (DES)

Корекции, открити при имплементацията. Всеки ред: секция, проблем, корекция, кой го откри.

| # | DES | Проблем | Корекция | Открито |
|---|---|---|---|---|
| 1 | §3.2 `risk.axes` | `reversibility:{ measured: paths }` без интервал след `:` не е валиден YAML mapping | `reversibility: { measured: paths }` в `testdata/php-symfony/riskrails.yaml` | вълна 0, strict parse тест |
| 2 | §3.2 `research.tech_docs` | няма поле за решението по §14.4 (Context7 зад флаг) | добавено `context7: false` (default off) в `core.TechDocsSpec` | вълна 0 |
| 3 | §3.3 | „празен файл = най-строго“ и „ceiling затяга“ не казват какво значи липсващо поле в ceiling | ceiling: липса = без ограничение; project: липса = `core.StrictDefaults()` | ревю на вълна 0 |
| 4 | §3.2 | няма поле за remote, „закован в ceiling.yaml“ (§3.4.3) | `remote: owner/repo`, само в ceiling | ревю на вълна 0 |
| 5 | §10 Claude, ADR-9 | hook `onFailure` по подразбиране е `continue`, не `block` | генераторът задава изрично `onFailure: "block"` (Claude Code ≥ 2.1.295) | W1-D, [V] |
| 6 | §3.4 стъпка 0 | sandbox-ът на Claude Code покрива само Bash; Edit/Write/Read, hooks и MCP са извън него | за Claude „границата“ е sandbox (Bash) + permission deny правила `Edit(...)`/`Read(...)` + hook; DES надценява стъпка 0 | W1-D, [V] |
| 7 | §3.2 → Claude rules | `Write(path)`, `NotebookEdit(path)`, `MultiEdit(path)` правила не съвпадат никога | генерира се `Edit(path)` | W1-D, [V] |
| 8 | §4.5(c) | PreToolUse за Agent носи `model` — потвърдено [V], но като alias (`sonnet`) | guard сравнява alias ↔ ID | W1-D contract тест |
| 9 | §3.2 `fail_closed`, ADR-9 | Codex hooks са fail-OPEN при crash/timeout/неподдържан изход (0.166.0) | адаптерът: всяко non-allow ⇒ exit 2; hook команда `rr guard … \|\| exit 2`; вътрешен deadline на `rr guard` 2 s < 10 s timeout; истинската граница е ОС sandbox | W1-E, [V] наблюдавано |
| 10 | §3.4 стъпка 0 (Codex) | `sandbox_mode` / `[sandbox_workspace_write]` не изразяват правила по път | ползват се permission profiles (`default_permissions` + `[permissions.*.filesystem]`); EACCES/EROFS проверено с `codex sandbox` | W1-E, [V] contract тест |
| 11 | §8.2 | `codex exec -a never` не съществува; `--full-auto` е отхвърлен | `codex exec -c approval_policy=never` | W1-E, [V] |
| 12 | §8.1–8.2 (Codex) | PreToolUse не поддържа `ask` | Ask ⇒ deny на всяко ниво под Codex; L0/L1 `unlisted: ask` блокира | W1-E, [V] |
| 13 | §3.2 `egress` (Codex) | allow-list за домейни не е налагаем без експерименталния `network_proxy`; мрежата е изцяло off | под Codex egress = всичко off; отворен въпрос за P3 | W1-E |
| 14 | §6 (Codex) | `.git` е read-only в sandbox-а ⇒ агентът не може да commit-ва | commit-ът е на runner-а/хоста | W1-E |
| 15 | §3.4 стъпка 0 (Codex) | permission profile: glob пътища поддържат само `deny`; `read` (read-only) иска точен път или `dir/**`; вложени read-only правила с липсваща цел чупят bwrap | read-only за slash-less globs (`.env*`, вложени `riskrails.yaml`) отпада под Codex → покрити само от fail-open hook; secret reads (deny) покриват всяка дълбочина | W1-E fix 1, [V] `codex sandbox` |
| 16 | §3.4, §16 (state) | `rr guard` пуска `git` в hook процеса, ИЗВЪН sandbox-а, в repo с конфигурация, която агентът може да е отровил (`core.fsmonitor`, `.git/commondir` → чужд gitdir) ⇒ изпълнение на код на хоста при всеки tool call | (1) `core.AlwaysProtected` = `.git/**`; (2) всяко извикване на git от `rr` е с `-c core.fsmonitor=false -c core.hooksPath=/dev/null …`, без global/system config и без наследени `GIT_*` | ревю рунд 3 (Opus), възпроизведено; регресионен тест |
| 17 | §6 (factory) | с `.git/**` под write-deny агентът не може да прави `git commit` и под Claude, и под Codex | commit-ите са на `rr` (factory, атомарен commit на стъпка) / runner-а / човека, извън sandbox-а | следствие от #16 и #14 |
| 18 | §5.2 llms.txt | `@doc-version` е дадено като [V], но спецификацията на llmstxt.org няма такъв маркер | tech-docs скаутът ползва версията, посочена в документа, и я сравнява с lockfile-а | W2-E, [V] |
| 19 | §5.2 Context7 | версията се подава само в текста на заявката, не като параметър на API-то | скаутът проверява версията в отговора; остава зад `context7: false` | W2-E, [V] |
| 20 | §5.4 merge | Jaccard ≥ 0.8 върху всички думи слива твърдения с различна ключова дума или с различни числа (redis/memcached, 1.5/5.1) | сливат се само твърдения с идентични съдържателни думи, полярност и поредица от числа; всичко сходно, но различно ⇒ CONFLICT | ревю W2-E, възпроизведено |
| 21 | §3.2 modes, §8.1 | `programme` е над `full_irreversible` в реда на режимите ⇒ задача, която е и двете, губи L0 пода | `core.Weight.Irreversible` се пази независимо от mode и никога не се сваля; autonomy (W3-A) ⇒ L0 при флага | ревю W2-A |
| 22 | §4.3 | кеш с TTL не е детерминистичен за committed манифести (`rr sync --check` в CI няма кеш) | committed `.rr/tiers.lock` (само PASS модели, без timestamps); всеки модел трябва да е кандидат в политиката за своя tier, иначе отпада | собственик, W2-B |
| 23 | §6 (Claude Code) | `isolation: worktree` тръгва от default branch-а, не от текущия HEAD | factory управлява собствени worktree-та за стъпките | W2-F, [V] |
| 24 | §6, errata #16 | worktree-ът на стъпката е под контрола на работника: подменен `.git` файл → чужд gitdir с `filter=` ⇒ код на хоста при `git add` от rr | всяка git операция с изрично `--git-dir`/`--work-tree`; `core.attributesFile=/dev/null`, `GIT_ATTR_NOSYSTEM=1`; `filter`/нестандартен `merge` атрибут ⇒ BLOCKED; commit-ва се точно прегледаното дърво; само обикновени файлове | ревю W2-F, възпроизведено + negative control |
| 25 | §9.2 | verify с доверени входове от CLI/работното копие дава фалшиво зелено (`full_run_when: []`, pty за `--scope`, `--base=--output=`) | verify секцията идва от ефективната политика; scope, base_sha, baseline manifest и mode идват само от `task_started` (W4-A ги пише); непокрит файл ⇒ full run винаги | ревю W2-C, възпроизведено |
| 26 | §8.2 (за W3-A) | close run-ът изпълнява тестове, написани от агента; извън sandbox-а те могат да подправят `.rr` | close run-ът се пуска в sandbox-а | ревю W2-C |
