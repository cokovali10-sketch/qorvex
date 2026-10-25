# ◈ Qorvex — AI Code Verification Platform

**Build. Test. Verify.**

Масштабная open-source платформа для безопасного выполнения, проверки и аудита кода, создаваемого AI coding agents.

## 🚀 Быстрый старт

```bash
git clone https://github.com/cokovali10-sketch/qorvex.git
cd qorvex

# Запустить API сервер
go run ./cmd/qorvex

# Или собрать бинарник
go build -o qorvex.exe ./cmd/qorvex
./qorvex.exe check <project-id>
```

API сервер запускается на `http://localhost:8420`.

## 🏗️ Архитектура

```
Qorvex Platform
├── Go (Core)          — API, оркестрация, pipeline, policy, audit
├── Rust               — Execution Engine (sandbox, seccomp, namespaces)
├── Python             — Анализаторы кода (semgrep, bandit, regex)
├── TypeScript         — Web dashboard (React + Vite)
└── SQL (PostgreSQL)   — Хранение проектов, результатов, политик, аудита
```

### Ключевые компоненты

| Компонент | Язык | Назначение |
|-----------|-----------|
| **Execution Engine | Rust | Изолрованное выполнение недоверенного кода (seccomp + namespaces) |
| **Code Analysis Engine | Python | SAST, секреты, зависимости, качество кода |
| **Verification Pipeline | Go | 9 стадий: diff → структура → анализ → депы → секреты → сборка → sandbox → risk → report |
| **Policy Engine | Go | Декларативные правила (block / warn / warn |
| **Audit Log | Go | Imutable HMAC-подписанный лог |
| **Dashboard | TypeScript | React SPA, REST API `:8420` |
| **Forge MCP Integration | Python | 72 инструмента через MCP-сервер |

## 📊 API

```
GET    /api/v1/health              — проверка сервера
GET    /api/v1/projects            — список проектов
POST   /api/v1/projects           — создать проект
GET    /api/v1/projects/{id}      — детали проекта
POST   /api/v1/projects/{id}/checks — запустить верификацию
GET    /api/v1/checks/{id}        — статус проверки
GET    /api/v1/projects/{id}/findings — результаты
GET    /api/v1/policies           — список политик
POST   /api/v1/policies           — создать политику
GET    /api/v1/audit              — лог аудита
GET    /api/v1/audit/verify       — верификация аудит-лога
```

## 🐘 База данных

```bash
# PostgreSQL миграции
psql -U qorvex -d qorvex -f sql/migrations/001_initial_schema.sql
```

## 🧪 Тестирование

```bash
# Go
go test ./pkg/... -v -count=1 -race

# Rust
cargo test --manifest-path rust/Cargo.toml

# Python
python -m pytest python/ -v

# TypeScript
cd ts && npm test
```

## 🔒 Безопасность

- **Fail-closed** — невозможность запуска проверки = FAILED
- **Deny-by-default** — sandbox-контейнеры с минимальными привилегиями
- **Immutable audit** — HMAC-SHA256, защита от подделки
- **Политики** — декларативные, версионируемые, с `frozen`-режимом
- **Sandbox** — seccomp-bpf, namespaces, cgroups, rlimits

## 🔗 Интеграция с Forge

Qorvex использует [Forge AI Toolkit](https://github.com/cokovali10-sketch/forge-ai-toolkit) (72 инструмента)

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

См. [docs/ROADMAP.md](docs/ROADMAP.md)

## 📄 Лицензия

MIT — см. [LICENSE](LICENSE)

## 👤 Автор

**cokovali10-sketch**