# Errata към research-fable.md (DES)

Корекции, открити при имплементацията. Всеки ред: секция, проблем, корекция, кой го откри.

| # | DES | Проблем | Корекция | Открито |
|---|---|---|---|---|
| 1 | §3.2 `risk.axes` | `reversibility:{ measured: paths }` без интервал след `:` не е валиден YAML mapping | `reversibility: { measured: paths }` в `testdata/php-symfony/riskrails.yaml` | вълна 0, strict parse тест |
| 2 | §3.2 `research.tech_docs` | няма поле за решението по §14.4 (Context7 зад флаг) | добавено `context7: false` (default off) в `core.TechDocsSpec` | вълна 0 |
