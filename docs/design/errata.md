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
