# RiskRails v4 — архитектура и план (от нулата)

Автор на синтеза: Claude Fable 5.1 (STRONG), 2026-10-31.
Събиране: 13 скаута на FAST (Haiku, effort low, само четене): 9 във Фаза 1, 4 във Фаза 2.
Adversarial review: един агент на STRONG (Фаза 4), находките BLOCKER/HIGH са поправени като една партида (виж §15).

Означения: **[V]** потвърдено в първоизточник от скаут; **[U]** непотвърдено или вторичен източник; **[E]** оценка на автора без източник. Всеки факт носи URL на първоизточника, както скаутът го е докладвал.

---

## 1. Позициониране

**Какво е RiskRails v4.** Risk engine + enforcement за AI coding agents: измерва колко опасна е една промяна, избира процеса по измерването, компилира политиката на проекта към нативните права на runtime-а и налага човешките gates там, където агент не може да ги подправи (server-side). Не е методология и не е колекция от skills за добри практики.

**Двата диференциатора, потвърдени след втората вълна и тази проверка.**

1. **Изчислен риск триаж**, преизчисляван по реалния diff. AI-DLC избира „workflow from the request“ (README, [V]) — селекторът не е документиран като правило; Superpowers, GSD, BMAD, Spec Kit, OpenSpec избират по преценка на модел или човек. Никой от осемте не измерва — твърдение за отсъствие, [E] по прочетената документация, не [V].
2. **Политика, компилирана към нативен enforcement.** Cursor (`hooks.json`, `failClosed`, deny>ask>allow, [V]), Codex (hooks on by default, `permissionDecision: deny`, PreToolUse покрива MCP tools, [V]), Gemini (policy engine TOML, `decision: allow|deny|ask_user`, приоритети, [V]), Claude Code (managed deny не се override-ва, [V]) — всеки има свой механизъм, никой не го генерира от една политика на проекта.

**Съзнателно НЕ правим.**

| Оставяме на | Какво |
|---|---|
| OpenSpec | формат на спецификациите (delta specs ADDED/MODIFIED/REMOVED → archive) във full/programme |
| Superpowers | протокол implementer ↔ reviewer (brief/report файлове, статуси, двустепенно review) — ние го **налагаме**, не го пренаписваме |
| Addy / Superpowers skills | практически skills (API, UI, perf, security) |
| Runtime-ите | sandbox (Seatbelt, bwrap+seccomp, bubblewrap), permission диалози, context compaction |
| GitHub / GitLab | идентичността на одобряващия, защитата на branch-а, CODEOWNERS |
| Renovate / Dependabot | dependency updates и automerge след soak |

Ядрото не включва: migrations/adopt framework (4.4k реда днес), compact memory (3.8k), alias команди, ръчни hook манифести, pty-базирано одобрение, LOCAL model tier.

---

## 2. Архитектура

### 2.1 Компоненти

```
riskrails.yaml (repo, default branch)      ~/.config/riskrails/ceiling.yaml (извън repo-то)
            │                                            │
            └──────────── policy resolver ───────────────┘
                   effective = tighten(ceiling, default-branch, worktree)
                                     │
┌──────────────────────── rr (един статичен Go бинар, ~9k реда) ─────────────────────────┐
│ triage     measured weight (6 оси) → light/guarded/full/programme; rescore по diff      │
│ models     availability resolver: probe → cache → effective = allowed ∩ available       │
│ research   scout fan-out (роли, бюджет, cache по SHA), merge brief за силния модел      │
│ plan       DAG по файлова собственост, вълни                                            │
│ factory    worktree на работник, статуси, двустепенно review, ескалация, лимити         │
│ guard      shell AST (mvdan/sh) + path/egress правила → allow/ask/deny, fail-closed     │
│ verify     test адаптери, affected tests, правила за пълен run, „двата факта“           │
│ autonomy   L0–L4, unattended runner, kill switch, PR-only изход                         │
│ release    dry-run + preflight; публикува CI през OIDC                                  │
│ ledger     токени и цена по задача/фаза/tier от транскриптите                           │
│ journal    JSONL, append-only, audit-first; state е производен                          │
└──────┬──────────────┬──────────────────┬───────────────────────┬────────────────────────┘
       │ CLI          │ MCP server       │ hook адаптери         │ генератори (rr sync --check)
       ▼              ▼                  ▼                       ▼
  човек / CI     всеки runtime     claude / codex / gemini    .claude/settings.json, .codex/
  (`rr …`)       (tools)           cursor / kiro / copilot    config.toml + hooks.json,
                                   opencode                   .gemini/policies/*.toml,
                                                              .cursor/hooks.json, agents/*.md
                                                              с tier→model, AGENTS.md,
                                                              CODEOWNERS, rulesets JSON,
                                                              CI workflows (verify, release)
skills/ (Agent Skills, .agents/skills): rr-build, rr-ship, rr-release, rr-simplify, rr-status
— тънки, викат `rr`; един източник, рендериран за всеки runtime
```

### 2.2 Повърхности

| Повърхност | Кой я ползва | Защо отделна |
|---|---|---|
| **CLI `rr`** | човек, CI, hook-ове, skills | единствената логика; всичко друго е адаптер |
| **MCP server `rr mcp`** | runtime-ите, които могат да викат tools (всички 7 + OpenCode) | преносим слой за `triage`, `affected`, `research`, `status` без shell |
| **Hook адаптери** | Claude Code, Codex, Gemini, Cursor, Kiro, Copilot | PreToolUse → `rr guard --event <name> --stdin`; изход по формата на runtime-а |
| **Генератори** | `rr sync` | рендерира манифести от политиката + effective tiers; `--check` в CI пази drift |

### 2.3 Поток на една задача

```
rr task start "<goal>" --files …
   │
   ├─ 1. triage: weight (scope, behaviour, reversibility, domain, novelty, coverage)
   │      → mode light | guarded | full | programme ; autonomy level ≤ ceiling
   │      → journal: task_started {weight, mode, policy_sha, tiers_effective}
   │
   ├─ 2. research (по mode): 0 / 2 / 4–5 / 6 скаута на FAST, cache по commit SHA
   │      → .rr/research/<sha>/<role>.json ; merge brief ≤ 3k токена за планиращия
   │
   ├─ 3. plan (по mode): inline / plan mode / written (OpenSpec delta spec)
   │      → DAG: стъпки, файлове на стъпка, тестове на стъпка, after-зависимости
   │      → scope guard е въоръжен: edit извън файловете на стъпката → deny
   │      → human gate (L0/L1) или auto-accept (L2+, journal: plan_accepted {by: autonomy})
   │
   ├─ 4. factory: вълни; worktree на работник; implementer → report (DONE|DONE_WITH_CONCERNS|BLOCKED|NEEDS_CONTEXT)
   │      → всяка стъпка: нейните тестове; rr affected ; атомарен commit на стъпка
   │
   ├─ 5. verify: affected run на стъпка; пълен run при close или при тригер (lockfile, config, миграция, mode ≥ full)
   │      → rescore по реалния diff: reversibility/domain по съдържание, scope по файловете в diff-а (само нагоре);
   │        `start --amend` преизчислява всичките шест оси; mode само расте
   │
   ├─ 6. review: двустепенно (spec compliance → quality) на tier-а на mode-а; findings → една fix партида
   │      → рундове 1–2 на tier-а на mode-а, рунд 3 с reviewer един tier нагоре (вътре в effective); 4-ти е на човека
   │
   └─ 7. close: „двата факта“ (зелен verify на дървото сега; промени само в обхвата)
          → light: архив ; guarded/full: PR + required review ; L≥2: само PR, никога merge
          → journal: task_closed {facts, cost, review}
```

---

## 3. `riskrails.yaml`

### 3.1 Принципи

- **Един файл в repo-то, версиониран.** Чете се от **default branch** за всичко, което разхлабва; working tree може само да затяга (§3.4).
- **Таван извън repo-то** (`/etc/riskrails/ceiling.yaml`, managed/root-owned; или `~/.config/riskrails/ceiling.yaml`, който е в `sandbox.no_write` и чийто sha256 се записва в journal-а при `task start` и се проверява при всяка вълна и при close — разминаване ⇒ `REFUSE {CEILING_CHANGED}`): по модела на Kiro, където workspace правата живеят извън repo-то (`~/.kiro/workspace-roots/<hash>/permissions.yaml`, [U]) и на Claude Code, където `bypassPermissions`/`auto` не действат от project файл ([V] https://code.claude.com/docs/en/settings).
- **Tiers, не имена.** Моделите се описват по runtime, но задачите говорят само в tiers.
- **Всяка секция има safe default**, така че празен файл = най-строгото поведение.

### 3.2 Пълна схема с коментиран пример (PHP/Symfony)

```yaml
# riskrails.yaml — RiskRails v4, schema 1
schema: 1
project:
  name: shop-backend
  stack: [php, symfony, doctrine, phpunit]
  default_branch: main             # политиката „в сила“ се чете оттук (§3.4)

risk:
  axes:                            # 0..2 всяка; измерените са под, декларацията само вдига
    scope:        { measured: refs, bands: [0, 5] }          # 0 refs→0, 1–5→1, >5 или hot_path→2
    behaviour:    { declared: true, keywords: [transaction, lock, queue, async, cron, state, flush] }
    reversibility:{ measured: paths }
    domain:       { measured: paths, declared: true }
    novelty:      { declared: true, manifest_floor: 1 }      # composer.json в diff → ≥1
    coverage:     { measured: tests, test_globs: ["tests/**/*Test.php"] }
  modes:                           # сумата W избира режима
    light:     { max: 2 }
    guarded:   { min: 3, max: 7 }
    full:      { min: 8 }
    programme: { trigger: [spec, ">1 session", "files > 25"] }
  hard_floors:                     # независимо от W
    - { axis: reversibility, value: 2, mode: full }
    - { axis: domain,        value: 2, mode: full, review: security }
    - { both: [reversibility, domain], value: 2, mode: full_irreversible }
  hot_paths: ["src/Payment/**", "src/Security/**", "config/packages/security.yaml", "migrations/**"]
  domain:
    money:    ["src/Payment/**", "src/Invoice/**", "src/Tax/**"]
    identity: ["src/Security/**", "src/User/**", "templates/security/**"]
    personal: ["src/Customer/**", "src/Gdpr/**"]
    customer_visible: ["templates/**", "assets/**", "translations/**"]
  reversibility:
    needs_step:   ["config/**", "assets/**", ".env*"]                     # cache clear, deploy
    irreversible: ["migrations/**", "src/Command/*Migrate*", "infra/**"]  # данни, схема, infra
    irreversible_content: ["DROP ", "TRUNCATE", "DELETE FROM", "ALTER TABLE .* DROP"]
  rescore: { axes: [reversibility, domain], when: [verify, close], direction: up_only }
  policy_file_weight: { behaviour: 2, domain: 2 }   # промяна на този файл е винаги full (§3.4)

models:
  tiers_allowed: [FAST, BALANCED, STRONG]          # EXPERT липсва → никога не се иска
  by_runtime:                                      # tier → кандидати по предпочитание
    claude:  { FAST: [haiku], BALANCED: [sonnet], STRONG: [opus], EXPERT: [fable] }
    codex:   { FAST: [gpt-5-nano, gpt-5-mini], BALANCED: [gpt-5-mini], STRONG: [gpt-5.3-codex, gpt-5] }
    gemini:  { FAST: [gemini-2.5-flash], BALANCED: [gemini-2.5-flash], STRONG: [gemini-2.5-pro] }
    openrouter: { FAST: [meta-llama/llama-3.3-70b-instruct], BALANCED: [anthropic/claude-sonnet-4.5] }
  ladder:
    missing: { EXPERT: STRONG, STRONG: BALANCED, FAST: BALANCED }   # липсващ tier → съсед
    on_error: { rate_limit: wait_then_same, permission: mark_unavailable, not_found: mark_unavailable }
    never_downgrade_thinking: true                 # провалена мисловна задача не се повтаря на по-евтин tier
  effort: { FAST: low, BALANCED: medium, STRONG: high }
  budgets:                                         # токени на задача по режим ≈ 1.5× worst case от §7.1; превишение = REFUSE + въпрос
    light: 150k
    guarded: 900k
    full: 3M
    programme: 10M
  probe: { ttl_hours: 24, on_4xx: refresh, cache: "~/.cache/riskrails/models.json" }

autonomy:
  ceiling: L2                      # най-високото ниво, което repo-то допуска; effective = min(тук, ceiling.yaml)
  by_mode: { light: L2, guarded: L3, full: L4, full_irreversible: L0 }   # таван по режим; задача = min(ceiling, by_mode[mode])
                                   # Ln покрива unattended за режими до: L2 light, L3 guarded, L4 full (§8.1);
                                   # ако нивото на задачата не покрива режима ѝ, тя върви интерактивно (L1)
  output: pr_only                  # L≥2 завършва само с PR (draft), никога merge/push към default
  kill_switch:
    remote_file: ".rr/HALT"        # на default branch, четен през hosting API от runner-а (агентът не може да го push-не)
    poll_seconds: 60               # runner-ът (извън sandbox-а) проверява на 60 s и преди всеки tool call през hook-а
    on_read_error: halt            # грешка при четене = стоп
  unattended:
    container: required            # L≥2 работи само в контейнер/sandbox
    max_wall_minutes: 90
    max_tasks_per_day: 10

enforcement:
  protected_paths:                 # deny за write, независимо от стъпката
    - ".env*"
    - "config/secrets/**"
    - ".github/workflows/**"       # workflow е release/verify повърхност; промяна = full
    - "riskrails.yaml"             # едит само от човек или с full mode (§3.4)
  secret_reads: [".env.local", ".env.prod", "config/secrets/**", "~/.ssh/**", "~/.aws/**"]
  commands:
    deny:  ["git push --force*", "git push * main", "rm -rf /", "composer global *", "php bin/console doctrine:schema:drop*"]
    ask:   ["git push*", "git commit*", "php bin/console doctrine:migrations:migrate*", "composer require*"]
    allow: ["composer install", "php bin/phpunit*", "php bin/console cache:clear", "git status", "git diff*"]
    parser: ast                    # mvdan/sh; неразпознат възел → ask при L0/L1, deny при L≥2
    unlisted: ask                  # команда извън трите списъка; при L≥2 и в auto mode е deny
  egress:
    allow: ["packagist.org", "repo.packagist.org", "api.github.com", "symfony.com", "context7.com"]
    deny_default: true
  fail_closed: true                # hook crash/timeout = deny
  sandbox:                         # ОС-ниво; границата е тук, hook-ът е tripwire (§3.4 стъпка 0)
    required_from: L2              # без ОС sandbox autonomy се капва на L1
    readonly: ["riskrails.yaml", ".git/config", ".git/refs/remotes/**", ".github/**"]
    no_read:  ["$secret_reads", "~/.config/riskrails/**", "~/.cache/riskrails/**"]
    no_write: ["~/.config/riskrails/**", "~/.cache/riskrails/**"]

verify:
  adapters:
    - { name: phpunit, cmd: "php bin/phpunit", affected: "rr affected --phpunit" }
    - { name: lint,    cmd: "vendor/bin/php-cs-fixer fix --dry-run" }
  full_run_when: [lockfile, "config/**", ".github/**", "migrations/**", "uncovered_file", "mode>=full", close]
  suite_budget: 2                  # пълни run-а на задача; третият е на човека
  nightly_full: true
  selection_misses_metric: true    # journal: affected_run → full_run показа червено

release:
  ecosystem: composer              # composer | npm | pypi | cargo | go | docker | helm
  channel: tag                     # tag → CI публикува; агентът не държи credentials
  preflight: ["composer validate --strict", "composer audit", "rr changelog --check"]
  publish_via: ci_oidc             # Packagist: webhook on tag; Docker: GHCR през GITHUB_TOKEN

research:
  by_mode:
    light:     []
    guarded:   [code, test]
    full:      [code, project-docs, tech-docs, prior-art, history]
    programme: [code, project-docs, tech-docs, prior-art, history, test]
  tier: FAST
  budget_per_scout: 80k
  cache: { key: [commit_sha, role, question_hash], dir: "~/.cache/riskrails/research/<repo-hash>" }  # извън write-set-а на агента
  tech_docs: { sources: [vendor, llms_txt, context7], pin_from: composer.lock }
```

### 3.3 Precedence (project / user / enterprise)

| Слой | Файл | Може да | Не може да |
|---|---|---|---|
| **enterprise/managed** | `/etc/riskrails/ceiling.yaml` (или MDM) | задава таван за autonomy, tiers, egress, protected paths | — |
| **user** | `~/.config/riskrails/ceiling.yaml` (no_write за агента, hash в journal-а) | затяга под enterprise; задава лични `by_runtime` кандидати | разхлабва enterprise; да бъде редактиран от агент (sandbox + hash) |
| **project (default branch)** | `riskrails.yaml` на `main` | всичко в схемата, до тавана | вдига над тавана (изрязва се тихо, journal `policy_clamped`) |
| **project (working tree)** | `riskrails.yaml` в checkout | само да **затяга** (по-нисък autonomy, повече protected, по-малко allow) | разхлабва (игнорира се до merge, journal `policy_loosening_ignored`) |
| **task** | `rr task start --mode full` | да вдига mode за една задача | да сваля mode (човек, `--by`, journaled) |

Правилото за сливане е монотонно: за всяко поле е дефинирана посока „по-строго“ (по-ниско autonomy ниво, по-малко allow, повече deny/protected, по-ниски прагове за `full`, по-високи тежести, по-малки бюджети) и effective е най-строгата стойност от слоевете. Това е еквивалентът на Claude Code „deny не се override-ва от по-нисък слой“ ([V]) и Kiro „deny > ask > allow независимо от scope“ ([U]).

### 3.4 Защита при разхлабване

Проблемът, потвърден от скаут 2: един project файл не може да спре агента да редактира **същия файл** в branch ([V] AVOID). Второ, по-дълбоко: всяка команда в `allow` (phpunit, composer scripts, `cache:clear`) изпълнява код, който агентът е написал — тест, който пренаписва `riskrails.yaml` или чете `.env.prod`, минава през hook-а като „разрешена команда“. Затова механизмът има нулева стъпка на ниво ОС и четири слоя отгоре; всеки е самостоятелен:

0. **Границата е ОС sandbox-ът, hook-ът е tripwire.** `rr sync` компилира `enforcement.sandbox` към нативния sandbox на runtime-а (Claude Code sandbox config, Codex `sandbox_mode`/`[sandbox_workspace_write]`, Docker mounts за runner-а): `riskrails.yaml`, `.git/config`, `.git/refs/remotes/**`, `.github/**` са read-only за процесите на агента; `secret_reads`, `~/.config/riskrails`, `~/.cache/riskrails` са недостъпни за четене. Тест, който пише в `riskrails.yaml`, получава EACCES, не „allow“. Без ОС sandbox (`required_from: L2`) hook-ът остава единствената защита и autonomy се капва на L1 — записано в journal-а като `enforcement: hook_only`.
1. **Посоката на промяната се измерва детерминистично.** `rr policy diff --base <policy-in-force>` сравнява всяко поле по дефинираната посока и връща `TIGHTEN | LOOSEN`. Правила: поле без дефинирана посока (`verify.adapters.cmd`, `by_runtime`, `research.*`, имена на адаптери) — всяка промяна е LOOSEN; списъци от globs с deny-семантика (`hot_paths`, `irreversible`, `needs_step`, `protected_paths`, `secret_reads`, `domain.*`) се сравняват по **множеството файлове**, които покриват върху `git ls-files` на текущото дърво — ново множество, което не е надмножество, е LOOSEN (стесняване на `src/Payment/**` до `src/Payment/*.php` се хваща); `MIXED` е LOOSEN. Няма модел в тази преценка.
2. **Hook-ът отказва loosen edit от агент.** `riskrails.yaml` е в `protected_paths`; PreToolUse за Edit/Write върху него → `rr policy diff` върху предложеното съдържание → `LOOSEN` ⇒ deny с причина. Tighten edit ⇒ allow, но задачата става `full` (`policy_file_weight`). Това е tripwire-слой: истинската защита е стъпка 0 (файлът е read-only).
3. **Разхлабването влиза в сила само от default branch, прочетен откъдето агентът не може да пише.** При L≥2: runner-ът (процес извън sandbox-а) чете `riskrails.yaml` през hosting API (`GET /repos/{o}/{r}/contents/riskrails.yaml?ref=<default_branch>`) от remote, **закован в `ceiling.yaml`**, не от `.git/config`; `git update-ref` или `git remote set-url` в sandbox-а не променят нищо. При L0/L1: `git show origin/<default_branch>:riskrails.yaml`, с `.git/config` и `.git/refs/remotes/**` read-only от стъпка 0; без sandbox това е tripwire и нивото е ≤ L1. Working tree версия с `LOOSEN` се игнорира до merge (`policy_loosening_ignored`). Без remote изобщо: в сила е последният commit на default branch, а commit на `riskrails.yaml` е `ask` + `full`.
4. **Merge-ът е човешки на сървъра.** `rr sync` генерира: `CODEOWNERS` ред `riskrails.yaml @owner-team`; ruleset за default branch с „Require a pull request“, „Require review from Code Owners“ ([V] https://docs.github.com/…/about-protected-branches), „Dismiss stale approvals“ ([V]), „Require approval of the most recent reviewable push“ — „must be approved by someone other than the person who pushed it“ ([V]); per-team file-pattern required reviewers („For each team, you can specify a list of file patterns“, [V] available-rules-for-rulesets; плановата наличност и bypass поведението са [U], §14.1, затова `rr sync --check --remote` чете живия ruleset през API и **отказва L≥2, ако правилата липсват**). Required status check `rr policy check --base <default_branch>` е червен при `LOOSEN`, освен ако през reviews API има **approving review** от човек, който е член на code-owner екипа и не е авторът на PR ([V] авторът не може да одобри своя PR; Copilot reviews не се броят). Label не се ползва като доказателство: `pull-requests: write` е едно право и покрива откриване на PR, review и labels — **не може да се раздели** — затова проверката гледа кой е подал review-то (login + team membership през API), а не какво е закачено на PR-а. Приложението на runner-а никога не е code owner, което `sync --check --remote` също проверява.

Остатъчен [U]: дали `GITHUB_TOKEN`/App token може да подаде approving review. Проверката по стъпка 4 не зависи от това: review от App identity не е член на code-owner екипа и не се брои.

---

## 4. Model availability resolver

### 4.1 Факти, върху които стъпва

- Anthropic `GET /v1/models` връща `id`, `display_name`, `lifecycle (active|deprecated|retired)`, `line`, `capabilities`, `max_input_tokens`, cursor пагинация; retired модел „inference requests naming it fail“; **документацията не казва, че списъкът е филтриран по ключа/плана** ([V] https://platform.claude.com/docs/en/api/models/list).
- Грешки: 403 `permission_error` „Your API key does not have permission to use the specified resource“; 404 `not_found_error`; 429 `rate_limit_error`; 529 `overloaded_error`; 400 `invalid_request_error` е за параметри, **не** за недостъпен модел ([V] https://platform.claude.com/docs/en/api/errors).
- OpenAI `GET /v1/models` връща `data[].id, owned_by, shutdown_date`; **не казва дали филтрира по достъп** ([V]). OpenRouter `GET /api/v1/models` изисква bearer, връща pricing и `supported_parameters` ([V]).
- Claude Code с абонамент: „A restricted model is hidden from the `/model` picker“; `--model`/`ANTHROPIC_MODEL`/`model` setting **не се проверяват предварително** и грешката идва на първата заявка; „Neither Fable model is the account-type default on any plan“ ([V] https://code.claude.com/docs/en/model-config). Subagent `model:` с блокиран alias → най-новата разрешена версия от същото семейство, друга блокирана стойност → наследява модела на сесията с предупреждение ([V] sub-agents). **Какво става, когато планът (не org allowlist) няма модела, не е документирано** ([U]).
- Codex: `[agents] default_subagent_model`, `default_subagent_reasoning_effort`, per-agent `model` ([V] learn.chatgpt.com/docs/agent-configuration/subagents). OpenCode: `opencode models <provider>`, „Model not found“ при липсващ ID ([U]). Gemini: `model.name` в settings, няма endpoint за наличност ([U]).

### 4.2 Алгоритъм

```
resolve(runtime, account):
  allowed   = policy.models.tiers_allowed ∩ ceiling.tiers_allowed
  catalogue = probe(runtime, account)                     # §4.3
  available = { tier : първият кандидат от by_runtime[runtime][tier], който е в catalogue и е PASS }
  effective = allowed ∩ available
  for tier in [EXPERT, STRONG, BALANCED, FAST]:
      if tier ∉ effective: ladder[tier] = ladder.missing[tier] (транзитивно, в effective)
  if BALANCED ∉ effective: REFUSE("няма tier за сесията")   # единственият твърд минимум
  rr sync рендерира agents/*.md, config.toml, settings.json САМО с effective → липсващ модел не съществува в никой файл
  journal: tiers_resolved {runtime, effective, ladder, catalogue_sha, probed_at}
```

### 4.3 Probe → cache

1. **Списък (безплатен):** API ключ → list endpoint на доставчика. Не е доказано, че е филтриран по ключа ([V] за Anthropic и OpenAI), затова е само *кандидат-лист*.
2. **Потвърждение (почти безплатен):** една заявка с `max_tokens: 1` и 10-токенов prompt за всеки кандидат, който политиката изобщо може да поиска (≤ 4 модела на runtime). Класификация по `error.type`, не по status: `permission_error`/`not_found_error` ⇒ FAIL (unavailable); `rate_limit_error`/`overloaded_error` ⇒ UNKNOWN (запазва предишното състояние); 200 ⇒ PASS. `count_tokens` не е доказано безплатен и валидиращ модела ([U]), затова не се ползва като probe.
3. **Абонаментни runtime-и без API (Claude Code Pro/Max, Codex Plus/Pro):** няма endpoint. Източници, по ред: (а) runtime настройки (`availableModels`, managed); (б) профилът на инсталацията (`--plan max --fable no`, както днес); (в) **наблюдение**: грешка от вида „restricted by your organization“ или „issue with the selected model“ ([V] wording) в транскрипта/hook изхода ⇒ FAIL за този модел. (г) явен `rr models probe --runtime claude` който стартира `claude -p "ok" --model <alias> --max-turns 1` за всеки кандидат и чете exit/грешка — струва ~100 токена на модел.
4. **Кеш:** `~/.cache/riskrails/models.json` `{runtime, account_hash, model: {state, probed_at, error}}`, TTL 24 h; **4xx permission/not_found на работеща заявка ⇒ незабавен refresh на този модел**; квота/429 не променя наличността, само бюджета. Кешът е в `sandbox.no_write`; подправен PASS не е риск за безопасността (заявката се проваля при доставчика и моделът пада на FAIL), подправен FAIL само сваля tier — и двете се виждат в journal-а като `tiers_resolved` с различен `catalogue_sha`.

### 4.4 Поведение при липсващ tier

| Липсва | Действие | Journal |
|---|---|---|
| EXPERT | STRONG поема ролите на EXPERT (review full, architect); никога не се иска Fable | `tier_missing {EXPERT→STRONG}` |
| STRONG | BALANCED поема; **full mode добавя втори review pass** и autonomy пада с едно ниво (компенсира по-слабия reviewer) | `tier_missing`, `autonomy_clamped` |
| FAST | BALANCED поема скаутите, но броят им се намалява наполовина (бюджет) | `tier_missing {FAST→BALANCED}` |
| BALANCED | REFUSE: няма с какво да се работи | `refused {NO_TIER}` |

### 4.5 Грешка по време на работа

- `permission_error`/`not_found_error` на tier T: моделът се маркира FAIL, resolver-ът се преизчислява, манифестите се рендерират наново, задачата продължава на `ladder[T]` **само ако стъпката е изпълнителска** (implementer, scout). Мисловна стъпка (plan, review, architect) **не се повтаря на по-евтин tier** (`never_downgrade_thinking`): задачата спира с `TIER_LOST` и въпрос към човека. (Правило на собственика; подкрепа: LLMRouterBench 2026 от предишната вълна — много рутери не бият baseline — [U], без URL в този документ.)
- `rate_limit_error`/`overloaded_error`: exponential backoff до 3 опита на същия tier; след това `QUOTA` и въпрос. Никога тихо надолу.
- **„Недостъпен модел не се иска“** е проверка, не обещание, в три части: (а) тест в `rr sync --check` fail-ва, ако някой генериран манифест съдържа модел с state ≠ PASS; (б) `Agent` повикване без `model:` наследява модела на сесията, който resolver-ът е избрал от effective — покрито по конструкция; (в) `Agent` повикване с изричен `model:` извън effective се отказва от hook-а — **при предпоставката [U], че PreToolUse input носи параметъра `model`**; тя се заковава с contract тест срещу pinned версия на всеки runtime, и ако тестът е червен, остават само (а)+(б) и journal-ът го отбелязва.

---

## 5. Research factory за spec/plan

### 5.1 Какво показаха самите скаути в това проучване

| Скаут (Haiku, low) | Токени | Tool calls | Време |
|---|---|---|---|
| model availability | 65k | 13 | 43 s |
| config precedence | 73k | 16 | 52 s |
| research patterns | 48k | 9 | 47 s |
| version-pinned docs | 50k | 12 | 50 s |
| prior-art | 51k | 12 | 42 s |
| token economics | 76k | 17 | 45 s |
| AI-DLC / Cursor | 51k | 8 | 51 s |
| Codex / Gemini | 56k | 25 | 57 s |
| core language | 50k | 11 | 37 s |
| Фаза 2 (4 тесни) | 46–71k | 8–9 | 26–30 s |

Среден скаут ≈ **57k токена, ~45 s**, паралелно. При Haiku 5.5 ($0.10/MTok input ≤100K, [V] pricing таблица) един скаут е под $0.05 за входа; изходът е ≤500 думи. Това е анкерът за бюджетите долу.

### 5.2 Роли

| Роля | Чете | Връща | Кога |
|---|---|---|---|
| **code-scout** | repo: `grep -n`, ast-grep, `git log -S`, Serena `find_symbol` (ако е инсталиран) | FACTS за имплементацията, callers, hidden coupling; TOUCHES: файлове | guarded+ |
| **test-scout** | тестове на засегнатите файлове, фикстури, CI конфиг | кои тестове покриват, кои липсват; affected списък; характеризационни пропуски | guarded+ |
| **project-docs-scout** | README, ADR, docs/, specs, CHANGELOG | решения, които задачата не може да наруши; отворени въпроси от ADR | full+ |
| **tech-docs-scout** | docs на зависимостите **във версията от lockfile**: `vendor/<pkg>/{README,CHANGELOG,docs}`, `llms.txt` с `@doc-version` ([V] Next.js), Context7 с версия в заявката и **проверка**, че върнатата версия = lockfile ([V] README: версията се подава в prompt-а, падането към latest е тихо [U]) | API facts за точната версия; breaking changes между lockfile и latest | full+ |
| **prior-art-scout** | repo helpers, `vendor/`, Packagist p2 / PyPI JSON / npm search, OSV `querybatch` (без лимит, [V]), Scorecard API ([U]) | кандидати за reuse с лиценз, последен release, OSV статус | full+ |
| **history-scout** | journal, `git log` на файловете, known-risks, past reviews | предишни провали на същите файлове, отворени рискове | full+ |

Всяка роля получава: цел, **вече известното** (за да не повтаря), схема на изхода, списък на инструменти/източници, граници, бюджет — четирите елемента, които Anthropic описва за subagent brief ([V] multi-agent post).

### 5.3 Колко на всяко ниво

| Режим | Скаути | Бюджет (вход+изход) | Паралелно |
|---|---|---|---|
| light | 0 — само `rr affected`, `grep -n`, `rr recall` | 0 модел-токени | — |
| guarded | code, test (2) | ≤ 160k | 2 |
| full | code, project-docs, tech-docs, prior-art, history (5) | ≤ 400k, + Фаза 2 ≤ 250k | 5 |
| programme | 6 роли на spec; code + test отново на всеки epic | ≤ 500k на spec + Фаза 2 ≤ 250k; ≤ 150k на epic | ≤ 6 |
| Фаза 2 (противоречия) | ≤ 4 тесни, една претенция всеки; само при full/programme | ≤ 250k | 4 |

Проверка срещу това проучване: 9 + 4 скаута за 735k е programme-spec (500k + 250k = 750k) — в бюджета. Една full задача на реален проект получава 5 + ≤4.

Опорна точка: Anthropic пуска „3–5 subagents in parallel“ за типична задача, „more than 10“ за широка ([V]); multi-agent е ~15× чат ([V]). Ние плащаме тези 15× само при full/programme, където spec фазата иначе е 28–44% от токените на силния модел.

### 5.4 Схема на изхода

```
FACTS:   - <твърдение> | <file:line или URL> | [V]/[U]
READ:    - <path> (всичко, което скаутът е отворил; ключ за invalidation)
TOUCHES: - <path> (файлове, които задачата ще пипа; само code/test scouts)
STEAL:   - <механизъм> → <компонент>
AVOID:   - <антипатерн>
GAPS:    - <непроверено>
COST:    tokens=<n> calls=<n>
```

Под 500 думи, без проза. `rr research merge` парсва схемата (ред по ред, детерминистично), **дедуплицира FACTS по нормализиран source + similarity на твърдението (Jaccard над токени ≥ 0.8), но никога не слива два факта с различна полярност (не/без/never) или различни числа — те се запазват като `CONFLICT` за Фаза 2**, събира GAPS и ги маркира като кандидати за Фаза 2, и записва merge brief ≤ 3k токена за силния модел. Силният модел чете само brief-а и файловете, които brief-ът цитира като решаващи.

### 5.5 Cache по commit SHA

Ключ `(commit_sha, role, sha256(question))` → `~/.cache/riskrails/research/<repo-hash>/<sha>/<role>-<qhash>.json` (извън write-set-а на агента; `.rr/` в repo-то държи само journal файловете на задачите (§16), които са hash-chained — всяко събитие носи sha256 на предишното, така че подмяна се вижда). Правила за invalidation: code/test — ако `git diff --name-only <sha>..HEAD` пресича READ (не само TOUCHES); tech-docs — ако lockfile hash се смени; prior-art — TTL 7 дни; project-docs — ако docs/ или ADR се сменят; history — винаги свеж (евтин). Два скаута с еднакъв ключ в един run = един. (Скаут 6 не намери публикувана практика за SHA-кеш — [U] по източник, детерминистично по конструкция.)

### 5.6 Как силният модел слива

1. Чете merge brief (≤3k) + GAPS.
2. Решава дали GAPS влияят на решение → пуска ≤4 тесни скаута (Фаза 2), всеки с **една** претенция.
3. Пише spec (OpenSpec delta) / plan (DAG) с цитати към FACTS.
4. Никога не чете суров уеб или файл >500 реда; ако му трябва, иска скаут с `file:line` excerpt.

---

## 6. Implementation factory

- **DAG по файлова собственост.** Всяка стъпка декларира файловете си; две стъпки с пресичане са `after`-зависими. Вълна = множество стъпки без пресичане. Проверката е детерминистична (`rr plan check`), преди всяка вълна.
- **Работник = свеж subagent в собствен worktree** (Claude: `isolation: worktree`, ≤20 едновременно, дълбочина 3; Codex: `agents.max_concurrent_threads_per_session` [V]; Gemini: `.gemini/agents/*.md` с `max_turns 30`, `timeout_mins 10` [V]). Brief файл in, report файл out (Superpowers модел). Контейнер вместо worktree при L≥2.
- **Статуси:** `DONE | DONE_WITH_CONCERNS | BLOCKED | NEEDS_CONTEXT`; `BLOCKED` спира вълната, `NEEDS_CONTEXT` пуска code-scout и повтаря веднъж.
- **Двустепенно review:** (1) spec compliance срещу delta spec и DAG; (2) качество (adversarial). Reviewer е свеж, чете diff + brief, връща FINDINGS по severity + VERDICT. BLOCKER/HIGH ⇒ една fix партида от паралелни fixer-и на BALANCED.
- **Ескалация:** рундове 1–2 на tier-а на mode-а; рунд 3 с reviewer един tier нагоре (ако е в effective, иначе същият tier с втори независим reviewer); четвъртият рунд е на човека (`REVIEW_BUDGET`). Една таблица на record: §7.1.
- **Лимити (политика):** `parallel ≤ 3` на BALANCED, `≤ 6` на FAST; `max_turns` на работник 30; report ≤ 1.5k токена; атомарен commit на стъпка (GSD) за bisect/undo; `suite_budget 2`.
- **Serial by default.** Паралелно писане само при доказано непресичащи се файлове; при съмнение (общ файл, генериран код, lockfile) — серийно.

---

## 7. Токен модел

### 7.1 Очакван разход по режим и фаза — таблицата на record ([E], анкери: измерени скаути ≈57k; Claude Code „agent teams ≈7× standard session“ [V]; multi-agent ≈15× chat [V])

„Типично“ = един review рунд, affected зелен, без Фаза 2. „Worst“ = всички капове изчерпани: Фаза 2, три review рунда (третият ескалиран), две fixer партиди, един NEEDS_CONTEXT re-scout, липсващ STRONG (втори review pass), 3 retry-а на 429, един re-render на манифестите след 4xx (губи cache за един turn).

| Фаза | light | guarded | full | programme (spec + 1 epic) |
|---|---|---|---|---|
| triage (детерминистичен) | 0 | 0 | 0 | 0 |
| research (FAST) | 0 | ~120k | ~300k | ~450k + ~150k |
| Фаза 2 скаути (FAST, само full+) | 0 | 0 | 0 / ≤250k | 0 / ≤250k |
| plan (BALANCED/STRONG) | ~5k | ~30k | ~80k (STRONG) | ~150k |
| implement (BALANCED) | ~40k | ~150k | ~500k | ~1.5M |
| verify (0 модел; log-reader на FAST при червено) | ~5k | ~20k | ~40k | ~80k |
| review рунд 1 (две стъпки) | 0 / ~30k при червен факт | ~60k (BALANCED) | ~200k (STRONG) | ~400k |
| review рундове 2–3 + fixer партиди (worst) | 0 | 0 / ~200k | 0 / ~600k | 0 / ~1.2M |
| втори review pass при липсващ STRONG (worst) | 0 | 0 | 0 / ~150k | 0 / ~300k |
| re-scout NEEDS_CONTEXT, 429 retry, re-render (worst) | 0 | 0 / ~80k | 0 / ~150k | 0 / ~300k |
| probe на модели (на 24 h, споделен между задачи) | ~1k | ~1k | ~1k | ~1k |
| close + ledger | ~2k | ~5k | ~10k | ~20k |
| **Типично** | **~55k** | **~390k** | **~1.1M** | **~2.8M** |
| **Worst** | **~85k** | **~670k** | **~2.3M** | **~5.3M** |
| Бюджет в `riskrails.yaml` (≈1.5× worst) | 150k | 900k | 3M | 10M |
| Цена, типично, при Haiku/Sonnet/Opus 5.5 вход $0.10/$2/$4 per MTok ([V] https://platform.claude.com/docs/en/build-with-claude/prompt-caching), изход [U] ≈5× входа, 70% cache hit | ~$0.06 | ~$0.7 | ~$3.5 | ~$9 |

Изходните цени за Claude 5.5 не бяха извлечени от официалната таблица ([U]); ledger-ът ги чете от транскриптите при първата реална задача и таблицата се преизчислява. `claude -p` probe зарежда целия system prompt, затова редът „probe“ е ~1k, не 100 токена.

### 7.2 Топ 10 мерки

| # | Мярка | Очакван ефект | Как се мери (ledger) |
|---|---|---|---|
| 1 | Триаж без модел; light без research/review | −100% на фазите за ~60% от задачите [E] | `tokens_by_phase` за light |
| 2 | Скаути на FAST, summary-only return (Claude: „return only the summary“ [V]) | research ×10 по-евтино от STRONG | `tokens_by_tier` |
| 3 | Стабилен prompt prefix + cache (read 0.1×; Sonnet/Opus 5.5 0.05×, Fable 0.025× [V]; минимум 512–4096 токена по модел [V]) | −50…70% вход на дълги сесии | `cache_read / input` ratio |
| 4 | Cache на research по SHA | −100% повторно research при resume/re-plan | `research_cache_hits` |
| 5 | `rr affected` вместо пълен suite на стъпка | −60…90% verify време; токени само при червено | `selection_misses`, `verify_seconds` |
| 6 | Merge brief ≤3k вместо суров изход на скаути | силният модел чете 10× по-малко | `strong_input_tokens` |
| 7 | Един always-loaded файл ≤ 60 реда + progressive disclosure на skills | −5…15k на всеки turn | `system_prompt_tokens` |
| 8 | Без смяна на модела на главната сесия (чупи cache); re-render на манифести след 4xx е изключението и се брои | запазва #3 | `cache_write_tokens` спайкове |
| 9 | Batch API за nightly/unattended research (50% [V] Anthropic, OpenAI, Gemini) — **само през API, не през Claude Code** ([V] costs page) | −50% на L≥2 research | `batch_share` |
| 10 | Лимит на рундове и fan-out от engine-а (3 review, 2 suite, parallel 3) | капа на опашката на провалите | `rounds_used`, `REFUSE` events |

Ledger: `rr cost` чете транскриптите на runtime-а (Claude JSONL, Codex sessions) при нула модел-токени, както днес `/rr-status --cost`; агрегира по task/phase/tier/model с list price и cache колони (Claude `/usage` дава per-model cache read/write [V]).

---

## 8. Автономия и одобрение

### 8.1 Нива

| Ниво | Кой решава | Допустим mode | Изход | Задължително |
|---|---|---|---|---|
| **L0** | човек: план, всяка стъпка, close | всички | commit от човека | — |
| **L1** | агент предлага, човек приема план и close (днешният guarded) | всички освен full_irreversible без confirm | commit/PR, избран в диалога | диалог |
| **L2** | агентът приема собствените си планове за **light**; човек само на merge | light | **draft PR** | контейнер, kill switch |
| **L3** | + guarded без човек до PR; авто-review (BALANCED) + required human review | light, guarded | PR | контейнер, CODEOWNERS |
| **L4** | + full (не irreversible) до PR; STRONG review; човекът одобрява само в GitHub | light, guarded, full | PR | всичко горе + rulesets `--check` зелен |

Семантика: Ln е капацитет — покрива unattended работа за режими до light (L2), guarded (L3), full без irreversible (L4). Нивото на една задача = min(`autonomy.ceiling` в repo, `ceiling.yaml` извън repo, `by_mode[mode]`). Ако нивото **не покрива** режима на задачата (пример: ceiling L2, задача guarded → L2 не покрива guarded), задачата върви интерактивно като L1; никога тихо на по-високо ниво. Така `by_mode` е таван по режим, не под, и L3/L4 са достижими, когато собственикът ги позволи. Никога без човек: full_irreversible, LOOSEN на `riskrails.yaml`, release publish, сваляне на mode, run над бюджет, изтриване с confirm. Повишаване на тавана е LOOSEN (§3.4).

### 8.2 Unattended runner

```
rr run --level L2 --queue <issues|plan> --runtime claude|codex|gemini
  - runner-ът е процес ИЗВЪН sandbox-а на агента; агентът е в контейнер (Docker sandbox / devcontainer)
    Codex: `codex exec --sandbox workspace-write -a never` (документирано за non-interactive [V];
           мрежата е OFF в workspace-write по подразбиране [V])
    Claude: `claude -p --permission-mode auto` + hooks + sandbox config от `rr sync`
    Gemini: `gemini -p` + policy TOML
  - `ask` НЕ съществува при L≥2 и в auto mode: `rr sync` компилира всяко `ask` към `deny` за всеки runtime
    (Cursor не налага `ask` в preToolUse [V]; Gemini `ask_user` ⇒ deny non-interactive [V]; Claude auto
    оставя класификатор да решава, което не е човек) ; неразпознат AST възел ⇒ deny ; `sync --check` го тества
  - GitHub App token: contents:write (branch), pull-requests:write (open PR) — едно право, което покрива и
    review и labels, затова нито label, нито review от App identity се броят за одобрение (§3.4 стъпка 4);
    App-ът не е code owner; без secrets за publish
  - kill switch: файл `.rr/HALT` на DEFAULT BRANCH, четен от runner-а през hosting API (contents:read),
    който агентът не може да push-не (protected); poll на 60 s + при всеки tool call hook-ът пита runner-а
    през local socket извън sandbox-а; грешка при четене = halt; `max_wall_minutes` е таван на вълна,
    не интервал на проверка. Локалният `.rr/HALT` в working tree е удобство за L0/L1, не защита.
  - преди всяка вълна: halt ? → stop ; бюджет ? → stop ; ceiling hash ≠ journal ? → stop
  - резултат: draft PR с task.md (weight, mode, research brief, review verdict, cost) ; label `rr:L2`
```

### 8.3 Server-side одобрение

Local approval е присъствие без идентичност — AI-DLC записва `session`, не човек ([V] aidlc-plan-approval-ask.ts), а текущият RiskRails признава pty подправяне. Затова: **одобрението, което брои, е review в GitHub/GitLab**, от човек ≠ pusher ([V] „most recent reviewable push … someone other than the person who pushed it“), върху защитен branch. Локалният диалог остава UX за L0/L1 и се journal-ва, но никога не замества server-side при L≥2 и при full.

### 8.4 Audit

Journal `.rr/journal.jsonl`: audit-first (събитието се записва преди промяната на state), регистър на събитията с тест за задължителните (взето от AI-DLC 131 events [V]), всяко събитие носи `task, actor (human|agent|autonomy|ci), via, policy_sha, tiers_effective`. `rr status` и `rr cost` са проекции над journal-а.

---

## 9. Модули 8–10

### 9.1 Release адаптери

Интерфейс: `Detect() bool · Preflight() []Check · DryRun() Result · PrepareTag(version) · CIWorkflow() yaml`. Агентът прави: changelog, bump, PR с tag; **CI публикува на tag през OIDC/trusted publishing**; агентът никога не държи publish credentials.

| Екосистема | Preflight / dry-run | Публикуване | Статус |
|---|---|---|---|
| npm | `npm pack --dry-run`, `npm publish --dry-run`, provenance | OIDC trusted publishing | P4 |
| PyPI | `python -m build`, `twine check` | trusted publishing (OIDC) | P4 |
| Composer/Packagist | `composer validate --strict`, `composer audit` | Packagist webhook на tag; няма publish стъпка | P4 (първи, PHP проектът на собственика) |
| Docker/GHCR | `docker build`, `trivy` (ако има) | `GITHUB_TOKEN` push | P4 |
| Helm | `helm lint`, `helm package` | OCI push към GHCR | P5 |
| Cargo | `cargo publish --dry-run` | crates.io trusted publishing [U] | P5 |
| Go | `go vet`, tag | proxy pull на tag | P5 |

### 9.2 Test impact (`rr affected`)

Интерфейс: `Map(changedFiles) → tests · Run(tests) · FullRunRequired(diff, policy) bool`. Първи адаптери: **phpunit** (mapping по namespace/autoload + файлово именуване `XTest.php`; Pest/phpunit-tia ако е инсталиран), **jest/vitest** (`--findRelatedTests` / `related`), **pytest** (testmon ако е инсталиран; иначе import graph), **go** (`go list -deps` обратно). Пълен run винаги при: lockfile, `config/**`, CI, миграции, непокрит файл, `mode ≥ full`, `close`. Nightly full run. Метрика `selection_misses`: affected зелено, пълен червено ⇒ запис + автоматично разширяване на mapping-а за тези файлове.

### 9.3 Simplify (`rr simplify` + skill)

Детерминистичен preflight: jscpd/PMD CPD дубликати, ast-grep правила на проекта, неизползвани символи (LSP/Serena при наличие — внимание: Serena е GPL-3 извън SolidLSP слоя [V], не се вгражда, само се вика). После един pass на BALANCED със същия brief като `/simplify` (reuse, simplification, efficiency), без bug hunting, `simplify-ignore` маркер (Addy). Skill-ът е `SKILL.md` в `.agents/skills/rr-simplify/`, което Codex сканира ([V] build-skills) и Claude чете; Gemini — [U] за Agent Skills, fallback: `rr simplify` като MCP tool.

---

## 10. Мулти-доставчик

| Runtime | Hooks (PreToolUse deny) | Нативни права | Sandbox | Subagents + model | Skills/AGENTS.md | Gap / degrade |
|---|---|---|---|---|---|---|
| **Claude Code** | да, exit 2 / JSON; timeout 600 s default, `onFailure: block` [V] | allow/ask/deny, managed deny неотменим, project не може bypass/auto [V] | bubblewrap/Seatbelt, `failIfUnavailable` | `model:` alias, blocked → inherit [V] | да | cloud sessions игнорират repo settings/hooks [V] ⇒ cloud = `ci_only`, таван **L1** |
| **Codex** | да, on by default, `permissionDecision: deny`, покрива MCP tools [V] | `approval_policy`, `sandbox_mode` | Seatbelt / **bwrap+seccomp** (Landlock legacy) [V]; MCP вътре/вън — [U] | `[agents]` model + concurrency [V] | `.agents/skills`, AGENTS.md [V] | project config само при trusted [V]; `--full-auto` deprecated [U] |
| **Gemini CLI** | BeforeTool deny (exit 2 / `decision: deny`) [V] | policy TOML, priority, admin tier [V] | — | `.gemini/agents/*.md`, `model` [V] | GEMINI.md; Agent Skills [U] | workspace policy tier „currently disabled“ [V]; tier номерата в docs са противоречиви [V] ⇒ тест при install |
| **Cursor** | 21 събития, `failClosed` (default false), deny>ask>allow [V]; чете Claude-style hooks само с opt-in setting [V] | hooks.json слоеве | — | subagentStart hook | AGENTS.md | `ask` в preToolUse не се налага [V]; user hooks не работят в cloud [V]; headless [U] |
| **Kiro** | PreToolUse block | permissions.yaml извън repo [U] | — | — | AGENTS.md | схемата се мени [U] |
| **Copilot (CLI/agent)** | ограничени | — | cloud | — | AGENTS.md | degrade: pre-commit + CI gates |
| **OpenCode / Goose / Aider** | без hooks | — | — | provider/model конфиг [U] | AGENTS.md | degrade: `rr guard` като pre-commit + CI `rr policy check` + `rr verify` |

**Degrade режим** (без hooks, и всяка cloud сесия, която не чете repo hooks): защитата е (1) CI required checks (`rr policy check`, `rr verify`, `rr close --check`) и (2) branch protection — единствените налагащи слоеве. Pre-commit hook `rr guard --staged` е **съвет**, не защита: `git commit --no-verify` го прескача. Агентът може да чете secrets локално. Journal-ът го отбелязва като `enforcement: ci_only` и autonomy се капва на **L1 без изключение**; §8.2 runner отказва да стартира `ci_only` проект на L≥2.

**Преносим слой:** AGENTS.md (стандарт) + `.agents/skills/` + `rr mcp` — трите, които всички runtime-и четат.

---

## 11. Технология

**Решение: Go, един статичен бинар `rr`.**

| Критерий | Go | Bun-compiled TS | Rust |
|---|---|---|---|
| Cold start hello-world | ~0.7 ms (startup-time bench, старо желязо [U]); ~40 ms с process spawn шум на 2019 MBP [U] | **без измерена цифра** [U]; runtime + JSC се вграждат | ~0.7 ms [U] |
| Размер на бинара | 2–10 MB [E] | **50–90 MB** по Bun docs [V]; 53–102 MB по платформа [U] | 1–5 MB [E] |
| Cross-compile | GOOS/GOARCH вградено | `--target` | `cross`/zig, по-тежко |
| Shell AST | **`mvdan/sh`**: POSIX/Bash/Zsh/mksh, BSD-3, активно [V] | tree-sitter-bash през WASM | tree-sitter-bash |
| MCP SDK | официален `go-sdk`, stdio, spec 2026-07-28 от v1.7.0 [V] | най-зрелият | `rmcp`, зрялост неясна [U] |
| Разпространение | GoReleaser → npm optionalDependencies (esbuild модел: shim + `require.resolve` + fallback download със SHA-256 [V]) + brew + `go install` | npm с 5× ~80 MB пакета | като Go |
| Скорост на итерация | висока | най-висока | по-ниска |

Hook-ът тече на **всеки** tool call; Claude Code казва „keep these hooks fast“ без цифра ([V]). Bun отпада заради размера на пакета (×5 платформи) и неизмерен старт. Rust отпада заради скорост на итерация и неясна зрялост на `rmcp`. Python (днешният) отпада: 20–50 ms старт и изисква интерпретатор на всяка машина.

Permission parsing-ът на самия Claude Code е AST (tree-sitter) с allowlist на node types и „too-complex ⇒ ask“ по изтекъл source ([U]) — същият fail-closed принцип приемаме за `rr guard`.

**Структура на repo-то (`agentic-risk-rails`):**

```
cmd/rr/                  main
internal/policy/         schema, resolver (tighten), diff (LOOSEN)
internal/triage/         weight, rescore
internal/models/         probe, cache, ladder, render
internal/research/       roles, briefs, merge, cache
internal/plan/           DAG, ownership
internal/factory/        workers, statuses, review loop
internal/guard/          shell AST, paths, egress
internal/verify/         adapters: phpunit, jest, pytest, go
internal/autonomy/       levels, runner, kill switch
internal/release/        adapters
internal/ledger/         transcript parsers, cost
internal/journal/        events registry, JSONL
internal/adapters/       claude, codex, gemini, cursor, kiro, copilot, opencode (hooks + generators)
internal/mcp/            server
skills/                  SKILL.md източници (rr-build, rr-ship, rr-release, rr-simplify, rr-status)
templates/               riskrails.yaml примери по stack, CODEOWNERS, rulesets, workflows
docs/adr/                ADR-и
```

Цел: ~9k реда Go (таблицата в §13 дава 8.9k) + ~1.5k реда skills/templates. Тестове: golden файлове за всеки генератор, contract тест на всеки hook адаптер срещу pinned версия на runtime-а, `rr sync --check` в собствения CI.

---

## 12. ADR-и

**ADR-1 Engine, не методология.** Контекст: 8 конкурента вече покриват spec/plan/skills. Решение: RiskRails измерва, налага и рутира; OpenSpec формат, Superpowers протокол. Отхвърлено: собствен spec формат. Последствие: по-малко ядро; зависимост от чужди конвенции, но само като формат.

**ADR-2 Go статичен бинар.** Контекст: hook на всеки tool call, 7 runtime-а, разпространение през npm/brew. Решение: Go + `mvdan/sh` + `go-sdk`. Отхвърлено: Bun compile (50–90 MB [V]), Rust (итерация, `rmcp` [U]), Python (старт, интерпретатор). Последствие: пренаписване от нулата; екипът трябва да е добър в Go.

**ADR-3 Политиката живее в repo-то, таванът извън него и извън write-set-а на агента, разхлабването само от default branch, прочетен през hosting API.** Контекст: project файл не може да пази себе си ([V]); allowed команди изпълняват кода на агента; локалните git refs са записваеми. Решение: §3.3–3.4 със стъпка 0 (ОС sandbox като граница). Отхвърлено: подписан policy файл (ключ на машината на агента = подправим); само CODEOWNERS (admin bypass по подразбиране [V]); label като доказателство за одобрение (`pull-requests: write` не се дели). Последствие: нужен remote, ruleset и ОС sandbox за L≥2; локални проекти без remote или без sandbox остават ≤ L1.

**ADR-4 Tiers + availability resolver, манифестите се рендерират от effective.** Контекст: list endpoints не доказано филтрират по ключ ([V]); Claude Code не проверява `--model` предварително ([V]). Решение: probe с `max_tokens:1`, кеш, `effective = allowed ∩ available`, генерираните файлове съдържат само effective. Отхвърлено: доверие в list endpoint; runtime fallback по време на работа за мисловни задачи. Последствие: един probe на 24 h; липсващ EXPERT е нормалното състояние, не грешка.

**ADR-5 Journal JSONL, audit-first, state е проекция.** Контекст: `state.py` монолит 5.4k реда с fallbacks. Решение: append-only събития с регистър и тест; `status`/`cost` са проекции. Отхвърлено: мутируем `state.json` като източник. Последствие: без migrations framework; проекциите се преизчисляват.

**ADR-6 Одобрението, което брои, е server-side.** Контекст: локалното одобрение е присъствие (AI-DLC [V], pty подправяне). Решение: GitHub review от човек ≠ pusher върху защитен branch; локален диалог е UX. Отхвърлено: подписано локално одобрение. Последствие: L≥2 изисква hosted git с rulesets.

**ADR-7 Research на FAST, синтез на STRONG, един adversarial reviewer.** Контекст: multi-agent ≈15× чат ([V]); скаут ≈57k токена (измерено). Решение: роли по режим, схема на изхода, merge brief, cache по SHA. Отхвърлено: research от главната сесия; флот от силни модели. Последствие: full/programme плащат ~300–500k на FAST, за да спестят STRONG токени.

**ADR-8 DAG по файлова собственост, serial by default.** Контекст: Superpowers е сериен, Codex предупреждава за конфликти. Решение: паралел само при доказано непресичане; worktree/контейнер на работник; атомарен commit на стъпка. Отхвърлено: свободен паралел с merge. Последствие: по-бавно при голямо пресичане, но без merge ад.

**ADR-9 Shell guard по AST, fail-closed, под ОС sandbox.** Контекст: regex е „tripwire“; и AST guard е tripwire, защото allowed команди изпълняват кода на агента. Решение: `mvdan/sh`, неразпознат възел ⇒ ask (L0/L1) / deny (L≥2), `unlisted: ask`/deny, `fail_closed: true` навсякъде, hook timeout кратък с `onFailure: block`; protected и secret paths се налагат от `enforcement.sandbox`, компилиран към runtime-а. Отхвърлено: regex като основа (остава втори слой); hook като единствена граница. Последствие: по-често `ask` при екзотични команди; L≥2 изисква sandbox.

**ADR-10 Test impact с твърд под за пълен run.** Контекст: Spec фаза и suite са най-скъпите части. Решение: `rr affected` на стъпка, пълен run при тригер и при close, nightly, `selection_misses`. Отхвърлено: само affected (пропуска интеграционни счупвания). Последствие: „двата факта“ остават с пълен run при close.

**ADR-11 Състоянието е journal на задача, знанието е в обикновените документи, всичко друго е проекция или кеш.** Контекст: днес `state.py` (5.4k реда) пази мутируем `state.json` с fallbacks и migrations, compact memory (3.8k реда) е отделна подсистема, а `.ai/project/` е генериран survey, който остарява. Решение: §16 — един append-only, hash-chained JSONL файл на задача (`.rr/run/` за текущата, `.rr/tasks/` за затворените, committed през PR-а на задачата); `status`, `cost`, `risks`, `recall` са проекции; знанието за проекта живее в `AGENTS.md`, `docs/`, `docs/adr/`, `specs/` по OpenSpec и `docs/known-risks.md`; изводимото (repo map, символи) се извлича при нужда и се кешира извън repo-то по SHA; `rr rebuild` възстановява всяка проекция и кеш. Отхвърлено: общ `journal.jsonl` за всички задачи (merge конфликти между разработчици); `state.json` като източник (migrations); генериран survey в repo-то (гние, агентът му вярва); отделна memory подсистема (journal-ът + `git log -S` дават същото). Последствие: няма migrations framework; промяна на знание (`AGENTS.md`, skills, ADR, spec) е задача с behaviour 2 и човешки merge; паметта не се пренася между машини иначе освен през git.

---

## 13. План по фази

| Фаза | Обхват | Критерий за готовност | Размер [E] |
|---|---|---|---|
| **P0 Core** | `rr` бинар; `riskrails.yaml` schema + resolver (tighten, LOOSEN diff по множества файлове); journal (hash-chained) + регистър; shell AST guard; `enforcement.sandbox` → Claude sandbox config + Codex sandbox_mode; hook адаптери Claude + Codex; `rr sync --check` за двата; `rr status` | PHP проектът на собственика работи в light/guarded под Claude и Codex; LOOSEN edit от агент е отказан в тест; тест, който пише в `riskrails.yaml` под sandbox, получава EACCES; `sync --check` зелен в CI | ~2.7k реда, 4 седмици |
| **P1 Triage + models + verify** | weight (6 оси, rescore), modes; availability resolver + probe + cache + рендер на tiers; `rr affected` (phpunit, jest, pytest, go); пълен-run правила; ledger (Claude, Codex транскрипти) | 13-те SQ1 случая от днешния weight минават; тест: манифест никога не съдържа FAIL модел; `selection_misses` се записва | ~2k реда, 3 седмици |
| **P2 Research + factory** | роли, briefs, merge, cache по SHA; DAG, ownership check, worktree работници, статуси, двустепенно review, ескалация, лимити | full задача на реален проект: ≤5 скаута, brief ≤3k, два review етапа, cost в ledger | ~1.5k реда, 3 седмици |
| **P3 Autonomy L0–L4** | нива, ceiling.yaml (hash в journal), runner извън sandbox-а, агент в контейнер (`claude -p`, `codex exec`), ask→deny компилация, PR-only, kill switch през hosting API, GitHub App, `sync --check --remote` (живи rulesets), генерирани CODEOWNERS/rulesets/CI `policy check` с reviews API | L2 run на light опашка завършва с draft PR без човек; HALT на default branch спира ≤60 s; LOOSEN PR е червен без approving review от code-owner човек; label от App-а не го прави зелен (тест) | ~1.2k реда, 3 седмици |
| **P4 Skills: release + simplify** | release адаптери composer, npm, pypi, docker + CI workflows през OIDC; `rr simplify` + SKILL.md | tag → CI публикува без credentials при агента; simplify работи в Claude и Codex на същия SKILL.md | ~0.8k реда, 2 седмици |
| **P5 Още runtimes** | Gemini (policy TOML, hooks, agents), Cursor (hooks.json + третия-страна loader), Kiro, Copilot, OpenCode/Goose degrade | contract тестове за всеки адаптер срещу pinned версия; degrade режим минава CI gates | ~1k реда, 3 седмици |

Общо ~9k реда Go, ~17 седмици за един човек с агенти. Между фазите: P0 е предпоставка за всичко; P1 и P2 могат да вървят паралелно след P0; P3 изисква P1; P4 и P5 са независими.

---

## 14. Рискове и отворени въпроси (само за собственика)

1. **GitHub план.** Per-team file-pattern required reviewers и „Restrict file paths“ са в rulesets ([V]), но плановата наличност и bypass поведението не са потвърдени ([U]). Ако проектите са на Free план, защитата на `riskrails.yaml` пада до CODEOWNERS + required status check. Решение: приемлив ли е този минимум за L≥2, или L≥2 изисква Team/Enterprise?
2. **Локални проекти без remote.** ADR-3 ги оставя на ≤ L1. Достатъчно ли е, или искаш локален „policy lock“ (hash в `~/.config`, подписан от човек) като алтернатива?
3. **Fable/EXPERT.** Fable никога не е default ([V]); при `--fable no` EXPERT не съществува. Да остане ли EXPERT изобщо в схемата, или STRONG е таванът на v4 и EXPERT влиза, когато има повече от един кандидат?
4. **Context7 зависимост.** Версията се подава в prompt, падането към latest е тихо ([U]). Да приемем ли `vendor/` + `llms.txt` като единствени задължителни източници, а Context7 като опция зад флаг?
5. **Serena (GPL-3).** Само извикване като външен MCP, никога вграждане. Потвърди.
6. **Пълен suite при close.** Остава (ADR-10). Ако искаш light да затваря само с affected, кажи — това сваля „двата факта“ до един.
7. **Codex MCP в sandbox** — [U]. До потвърждение MCP сървърите под Codex се третират като извън sandbox. `rr guard` на PreToolUse вижда аргументите на MCP повикването (PreToolUse покрива MCP tools [V]), **не** мрежата на сървъра — egress за MCP е tripwire по аргументи, инференция, не enforcement. Ако това не стига, MCP сървърите за L≥2 се пускат в контейнера на runner-а с неговата мрежова политика.
8. **Gemini Agent Skills** — [U]. Ако липсват, simplify и build skills под Gemini вървят само като MCP tools.
9. **Име и пакет.** `agentic-risk-rails` като ново repo и `rr` като бинар, без обратна съвместимост с `.ai/` и `state.py`. Потвърди, или искаш `rr adopt` от 3.x в P5.
10. **Екип на Go.** Пренаписването е ~9k реда; ако екипът е по-бърз на TS, Bun остава легитимна алтернатива с цената от §11.

---

## 15. Отчет за изпълнението

**Агенти.** 13 на FAST (Haiku, effort low, read-only): 9 Фаза 1 + 4 Фаза 2. 1 на STRONG за adversarial review (Фаза 4). 0 на EXPERT. Синтезът — тази сесия (Fable 5.1).

**Токени (от task notifications).** Фаза 1: 521k. Фаза 2: 213k (71k + 46k + 46k + 50k). Общо скаути ≈ **735k** на Haiku. Сесията (четене на Фаза 0 + 13 доклада + синтез): [E] ~150k. Review: [E] ~60k.

**Adversarial review (Фаза 4, 1 агент на STRONG/Opus, 76k токена).** VERDICT FAIL на първата версия: 4 BLOCKER (allowed команди изпълняват кода на агента и заобикалят hook-а; локалните git refs/remote са подправими; `pull-requests: write` не се дели и label е самоодобрим; ceiling.yaml и кешовете са записваеми от агента), 6 HIGH (L3/L4 недостижими при `by_mode`; `ask` при L≥2 става allow/класификатор; LOOSEN без посока за unordered полета и MIXED; kill switch в working tree; pre-commit в degrade се прескача с `--no-verify`; бюджетите не са 3×), 5 MEDIUM. Всички BLOCKER и HIGH са поправени като една партида (§3.2 `sandbox`, §3.4 стъпки 0–4, §8.1 семантика на нивата, §8.2 runner, §10 degrade, §7.1 таблица на record); от MEDIUM са поправени скритите разходи, дедупликацията по полярност, READ-базираната invalidation, числовите несъответствия и етикетите [V]/[U]/[E]. Втори review pass не е пускан (бюджет: един reviewer); остатъчните рискове са в §14.

**[U] твърдения: потвърдени.**
- „multi-agent ≈15× tokens than chats“ — дословно [V].
- AI-DLC: 11 профила, 131 audit събития, версия 2.11.2, Bun се ползва, `HUMAN_TURN` съществува, одобрението записва `session`, не човек; guard policy има `strict|relaxed|off` [V].
- Cursor зарежда Claude-style hooks — **само с opt-in setting** „Include Third-Party Plugins…“; `failClosed` съществува, default false; 21 събития; project hooks работят в cloud, user hooks не [V].
- Codex: hooks съществуват и са on by default, deny през `permissionDecision`/exit 2, PreToolUse покрива MCP tools; `[agents]` с concurrency и default model [V].
- Gemini: hooks (BeforeTool deny), policy engine TOML с приоритети и admin tier, subagents с `model` [V].

**[U] твърдения: опровергани или коригирани.**
- Файл `aidlc-plan-approval-guard` не съществува; има guard fence „plan-approval“ и `aidlc-plan-approval-ask.ts`; `aidlc-hook-front-gate.ts` е **PostToolUse**, не PreToolUse блокер на едити [V].
- „Guard Policy off по подразбиране“ — не е намерено; default неизвестен [U].
- „Профилът се избира от LLM“ — README казва „selects a workflow from the request“; селекторът не е документиран [U].
- Codex Linux sandbox е **bwrap + seccomp по подразбиране**; Landlock е legacy опция [V]. `--full-auto` е deprecated [U].
- `bun build --compile` дословно не е намерен в `scripts/package.ts`; Bun се ползва [V].

**[U] останали.** Дали MCP под Codex е в sandbox-а; дали `GITHUB_TOKEN` може да одобри PR; дали Anthropic/OpenAI list endpoints филтрират по ключ; цена/валидация на `count_tokens`; Gemini Agent Skills; Cursor hooks в headless; плановата наличност на rulesets file-pattern reviewers; Bun cold start.

---

## 16. State и knowledge base

Принцип: за всяко нещо има едно място за истина; всичко друго е проекция или кеш, който `rr rebuild` възстановява с една команда. Ако нещо не може да се възстанови така, то е източник на истина и трябва да е committed.

### 16.1 State

| Какво | Къде | Git | Кой пише |
|---|---|---|---|
| Събитията на текущата задача | `.rr/run/<task-id>.jsonl` | ignored | само `rr` (през hooks/CLI); append-only, hash-chained |
| Логове, test output, worktrees | `.rr/run/<task-id>/…` | ignored | `rr` |
| Производен статус | `.rr/run/state.cache.json` | ignored | проекция, изтриваем |
| Затворена задача | `.rr/tasks/<task-id>.jsonl` + `.rr/tasks/<task-id>/task.md` | **committed** през PR-а на задачата | `rr close` |
| Индекс на задачите | `.rr/index.json` | ignored, генериран | `rr index` |
| Авторитетно копие при L≥2 | при runner-а, извън sandbox-а | — | runner; копието в repo-то се сверява при close |

- **Няма `state.json`.** `rr status`, `rr cost`, `rr risks`, `rr recall` са проекции над събитията. Всяко събитие носи `schema: 1` и `prev_sha256`; стари събития се четат по версия, непознати полета се пропускат. Няма migrations framework.
- **Един файл на задача.** Двама разработчици с паралелни PR-и не правят конфликт в append-only файл, който никой не редактира. Общ `journal.jsonl` е отхвърлен (ADR-11).
- **Audit-first.** Събитието се записва преди промяната; регистърът на събитията има тест за задължителните (`task_started`, `plan_accepted`, `verify_run`, `review_verdict`, `task_closed`, `policy_*`, `tiers_resolved`, `refused`).
- **Агентът не пише там директно.** `.rr/run/` се пълни от `rr`, извикан от hook-а; `.rr/tasks/` се пълни от `rr close`. Подмяна в sandbox-а се вижда по hash chain при close и при runner-а.

### 16.2 Knowledge base

Три вида знание, три собственика, без дублиране:

| Вид | Къде | Собственик | Как агентът го чете |
|---|---|---|---|
| Политика | `riskrails.yaml`; `ceiling.yaml` извън repo-то | човек (§3.4) | resolver |
| Знание за проекта | `AGENTS.md` (≤60 реда, единственият always-loaded); `docs/`; `docs/adr/`; `specs/` (текуща истина) и `changes/` → archive по OpenSpec; `docs/known-risks.md` | хора, през задача с behaviour 2 | AGENTS.md на всеки turn; останалото при нужда (project-docs-scout, `rr recall`) |
| Памет за свършеното | journal-ът + `task.md` на всяка затворена задача | `rr close` | `rr recall --files <paths> --budget <n>`: кои задачи са пипали файловете, review находки, отворени `risk_recorded`, `git log -S` |

- **Няма генериран survey в repo-то.** Днешното `.ai/project/` остарява и агентът му вярва. Изводимото от кода (repo map, символи, callers) се извлича при нужда от LSP/ctags/ast-grep и се кешира по SHA в `~/.cache/riskrails/repomap/<repo-hash>/<sha>/`.
- **Кешове, всички изхвърляеми и извън write-set-а на агента** (`sandbox.no_write`): research (`~/.cache/riskrails/research/…`), models (`~/.cache/riskrails/models.json`), repo map. Нищо в тях не е истина.
- **Промяна на знание е задача с тежест.** Редакция на `AGENTS.md`, skills, ADR или spec върви с `behaviour: 2` както `policy_file_weight`, защото сменя кой какво прави. Агентът я предлага в PR, човек я merge-ва.

### 16.3 Правила

1. **Преносимост.** Всичко от 16.1 и 16.2 е в repo-то, затова Claude, Codex и Gemini виждат същото. В `~/` стоят само ceiling-ът и кешовете.
2. **Размер.** Always-loaded ≤60 реда; progressive disclosure за skills; `recall` в токен бюджет (подразбиране 4k). Пълният journal никога не влиза в контекста, влизат проекции.
3. **Възстановяване.** `rr rebuild` преизчислява индекса, кешовете и проекциите от `.rr/tasks/` и git. `rr doctor` проверява hash chain-а и че всяка затворена задача има `task.md`.
4. **Compaction.** При compaction на сесията `rr handoff` записва в `.rr/run/<task-id>/handoff.md` решенията и причините, отхвърлените варианти, точните пътища, провалените опити с грешката, отворените въпроси и последната инструкция; следващата сесия го чете преди всичко друго. Това е проекция на journal-а плюс текущия diff, не отделен източник.
5. **Един разработчик, една задача на checkout.** `.rr/run/` е за текущия checkout; втора задача в същия checkout е `REFUSE {TASK_IN_FLIGHT}`; worktree на работник има свой `.rr/run/`.

Какво замества от днешния код: `state.py` state machine + fallbacks, compact memory (`memory enable/pack/verify/cleanup`, 3.8k реда), migrations 0007–0011, `.ai/project/` survey, `.ai/state/handoff.md` като отделен формат. Остава същото по същество: append-only journal, `recall --files`, handoff преди compaction, честен known-risks.
