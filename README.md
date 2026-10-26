# ◈ Qorvex — AI Code Verification Platform

**Build. Test. Verify.**

Платформа для безопасной проверки и аудита кода, создаваемого AI coding agents.
Fail-closed пайплайн, встроенный сканер секретов, dependency-аудит, изолированное
выполнение и неизменяемый HMAC-подписанный аудит.

```
Go core · Rust sandbox · Python analyzers · TypeScript dashboard · PostgreSQL
```

## 🚀 Быстрый старт

```bash
git clone https://github.com/cokovali10-sketch/qorvex.git
cd qorvex

# Запустить API-сервер (порт 8420)
go run ./cmd/qorvex

# Или собрать бинарник
go build -o qorvex.exe ./cmd/qorvex
./qorvex.exe
```

Порт можно переопределить: `QORVEX_PORT=9000 go run ./cmd/qorvex`.

### Первая проверка через API

```bash
# 1. Создать проект
curl -X POST http://localhost:8420/api/v1/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"demo","path":"D:/Projects/demo"}'

# 2. Запустить проверку (подставьте id проекта)
curl -X POST http://localhost:8420/api/v1/projects/<project-id>/checks

# 3. Смотреть статус, стадии и отчёт
curl http://localhost:8420/api/v1/checks/<check-id>
```

## 🏗️ Архитектура

```
Qorvex Platform
├── Go (Core)          — API, оркестрация, pipeline, policy, audit, store
├── Rust               — Execution Engine (sandbox, seccomp, namespaces, rlimits)
├── Python             — Анализаторы кода (semgrep + regex fallback, baseline)
├── TypeScript         — Web dashboard (React + Vite, 6 страниц)
└── SQL (PostgreSQL)   — Проекты, проверки, стадии, findings, политики, аудит
```

### Ключевые компоненты

| Компонент | Язык | Назначение |
|-----------|------|-----------|
| **Execution Engine** | Rust | Изолированное выполнение недоверенного кода (seccomp + namespaces + rlimits) |
| **Code Analysis Engine** | Python | SAST, секреты, зависимости, качество кода |
| **Verification Pipeline** | Go | 9 стадий с таймаутами, телеметрией и fail-closed семантикой |
| **Policy Engine** | Go | Декларативные правила `block` / `warn` / `allow` |
| **Audit Log** | Go | Неизменяемый HMAC-SHA256-подписанный лог |
| **Dashboard** | TypeScript | React SPA: проекты, проверки, стадии, findings, политики, аудит |
| **Forge Integration** | Go + Python | Адаптер к Forge AI Toolkit (72 инструмента) |

## 🔬 Verification Pipeline

Каждая проверка проходит 9 стадий. Статус, длительность и ошибка каждой стадии
сохраняются в `check_run.stages`.

| # | Стадия | Что делает | Critical |
|---|--------|-----------|----------|
| 1 | `diff_ready` | Проверяет доступность проекта, определяет VCS-состояние | ✅ |
| 2 | `structure_check` | Bounded-обход дерева, symlink escape, oversized-файлы | ✅ |
| 3 | `static_analysis` | Forge audit → fallback на Python-сканер | — |
| 4 | `dependency_scan` | govulncheck / npm audit / pip-audit / cargo audit | — |
| 5 | `secret_scan` | AWS/GitHub/Slack/Google ключи, private keys, JWT, generic credentials | ✅ |
| 6 | `build_and_test` | `go build`, `cargo check`, `npm run build`, `python compileall` | — |
| 7 | `sandbox_run` | Команда из `.qorvex/sandbox.json` в Rust-sandbox (если собран) | — |
| 8 | `risk_assessment` | Агрегирует severity → `low/medium/high/critical` | ✅ |
| 9 | `report_generation` | Формирует score, counts, SBOM-манифесты, summary | ✅ |

**Правила безопасности пайплайна:**

- путь проекта канонизируется, любой выход за root запрещён (`safeJoin`);
- обход ограничен 5000 файлами, глубиной 64 и файлами ≤ 1 MiB;
- внешние команды запускаются без shell, с таймаутом и лимитом вывода 64 KiB;
- секреты в placeholder-значениях (`changeme`, `your_...`) не считаются утечкой;
- критическая стадия с ошибкой → весь check `failed`;
- `risk_level=critical` → check `failed` даже при высоком score;
- все стадии пишут события в подписанный audit log.

## 📊 API

| Метод | Путь | Назначение |
|-------|------|-----------|
| GET | `/api/v1/health` | Проверка сервера |
| GET | `/api/v1/projects` | Список проектов |
| POST | `/api/v1/projects` | Создать проект |
| GET | `/api/v1/projects/{id}` | Детали проекта |
| POST | `/api/v1/projects/{id}/checks` | Запустить проверку |
| GET | `/api/v1/checks/{id}` | Статус, стадии и отчёт |
| GET | `/api/v1/projects/{id}/checks` | История проверок |
| GET | `/api/v1/projects/{id}/findings` | Findings проекта |
| GET | `/api/v1/policies` | Список политик |
| POST | `/api/v1/policies` | Создать/обновить политику |
| GET | `/api/v1/policies/{id}` | Политика по id |
| GET | `/api/v1/audit` | Последние записи аудита |
| GET | `/api/v1/audit/verify` | Проверка HMAC-подписей |
| GET | `/api/v1/audit/stats` | Статистика аудита |

## 🐘 База данных

```bash
psql -U qorvex -d qorvex -f sql/migrations/001_initial_schema.sql
psql -U qorvex -d qorvex -f sql/migrations/002_pipeline_telemetry.sql
```

`002` добавляет `check_stages`, `risk_level`, `severity_counts` и ослабляет
CHECK категорий для namespaced-значений (`forge-security`, `stage-error:*`).

## 🧪 Тестирование

```bash
# Go — 106 тестовых функций, 7 пакетов
go test ./pkg/... -count=1 -v

# Python — 9 тестов
cd python && python -m pytest tests -q

# Rust
cargo test --manifest-path rust/Cargo.toml

# TypeScript
cd ts && npm run build && npm test
```

Покрытые области: path traversal, bounded walk, таймауты команд, детекция
секретов и placeholder-фильтрация, парсеры npm/pip/cargo/govulncheck,
риск-модель, отчёт, API-контракты, HMAC-аудит, fail-closed пайплайн,
copy-on-read в store (защита от гонок).

## 🔒 Безопасность

- **Fail-closed** — ошибка критической стадии = `failed`, а не «пропущено».
- **Deny-by-default** — sandbox с минимальными привилегиями и rlimits.
- **Immutable audit** — HMAC-SHA256 по каждому событию, `/audit/verify`.
- **Path safety** — канонизация root, запрет absolute/`..` путей, symlink escape.
- **Resource bounds** — лимиты файлов, размера, глубины, времени и вывода команд.
- **Secrets hygiene** — ключи не логируются, в finding попадает только файл и строка.

## 🔗 Интеграция с Forge

Qorvex использует [Forge AI Toolkit](https://github.com/cokovali10-sketch/forge-ai-toolkit)
(72 инструмента). Адаптер: `pkg/forge/client.go`. Если Forge недоступен,
`static_analysis` автоматически переключается на Python-сканер.

```json
{
  "mcpServers": {
    "qorvex": {
      "command": "qorvex",
      "args": ["mcp"]
    },
    "forge": {
      "command": "D:/Forge-Factority/.venv/Scripts/python.exe",
      "args": ["-m", "forge.cli", "mcp"]
    }
  }
}
```

## 🗺️ Roadmap

См. [docs/ROADMAP.md](docs/ROADMAP.md). Текущий статус — v0.2.0:
реальный pipeline, телеметрия стадий, dependency-аудит и риск-модель.

## 📏 Масштаб

| Слой | Файлов | Строк |
|------|--------|-------|
| Go (core + tests) | 18 | 4 597 |
| Rust (sandbox) | 1 | 191 |
| Python (scanners + tests) | 4 | 492 |
| TypeScript (dashboard) | 10 | 741 |
| SQL (миграции) | 2 | 136 |
| **Код всего** | **35** | **6 157** |
| Документация | 8 | 653 |
| Конфигурация (без lockfile) | 9 | 184 |
| **Авторский итог** | **52** | **6 994** |

`package-lock.json` (2 627 строк) не входит в авторский масштаб.

## 📄 Лицензия

MIT — см. [LICENSE](LICENSE).

## 👤 Автор

**cokovali10-sketch**
