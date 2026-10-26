# Qorvex — Архитектура

> Версия: 0.2.0
> Статус: рабочий прототип

## 1. Цели и принципы

**Миссия:** дать разработчикам независимую, воспроизводимую и аудируемую проверку
кода, создаваемого AI coding agents.

**Принципы:**

1. **Fail-closed.** Невозможность выполнить проверку = провал (не успех).
2. **Deny-by-default.** Sandbox-контейнеры создаются со строгими профилями.
3. **Open source first.** Используем только открытые и лицензированные средства.
4. **Modular monolith → distributed later.** Сначала одна сервисная область, без распределения.
5. **No vendored magic.** Каждый компонент имеет контракт и тесты.

## 2. Компоненты платформы

```
┌─────────────────────────────────────────────────────────────────┐
│                         Qorvex Platform                           │
├─────────────────────────────────────────────────────────────────┤
│  Web Panel (TypeScript/React)          CLI (Go)                   │
│  Dashboard · Reports · Policies        `qorvex check`            │
├─────────────────────────────────────────────────────────────────┤
│  API Gateway (Go /chi)                                          │
│  REST · OpenAPI · AuthN/AuthZ                                   │
├──────────┬──────────────────────────────────────────────────────┤
│          │  Orchestrator (Go)                                    │
│          │  Job queue (in-memory / DB-backed)                   │
│          │  Pipeline state machine                               │
│          ├──► Execution Engine                                  │
│          │     └── Rust: namespaces, seccomp, namespaces, rlimits │
│          ├──► Code Analysis Engine                              │
│          │     ├── Python: scanners (semgrep, bandit, pip-audit) │
│          │     └── custom plugins                                │
│          ├──► Dependency & SBOM engine                         │
│          ├──► AI Agent Integration (adapters + MCP)             │
│          └──► Policy Engine + Audit Log                        │
├──────────┴──────────────────────────────────────────────────────┤
│  Storage: PostgreSQL (проекты, проверки, findings, политики,      │
│           аудит, SBOM). SQLite для локального режима.              │
└─────────────────────────────────────────────────────────────────┘
```

## 3. Языки и зоны ответственности

| Зона | Язык | Компоненты |
|---|---|---|
| Runtime / API / Orchestration / Queue | Go | основной сервис |
| Execution sandbox, low-level syscalls | Rust | exec isolation, seccomp, namespaces, rlimits |
| Analyzers, ML-интеграции, automation | Python | scanners, LLM-judge, report generators |
| Web panel, MCP client SDK | TypeScript | React SPA + Vite + MCP SDK |
| Миграции / метаданные | SQL | PostgreSQL migrations |

## 4. Структура каталогов

```
qorvex/
├── cmd/                    # Входные точки (main.go, cmd/qorvex)
├── pkg/                    # Go-пакеты ядра
│   ├── platform/          # Domain types (Project, Diff, Finding, CheckRun)
│   ├── orchestrator/      # Pipeline state machine
│   ├── api/                # REST handlers
│   ├── policy/            # Policy engine
│   ├── audit/             # Audit log
│   └── store/             # Storage ports/adapters
├── internal/              # Приватные Go-пакеты
├── rust/                   # Rust workspace (sandbox-exec, analyzer host)
├── python/                 # Python package (scanners, runner)
├── ts/                     # TypeScript web + MCP клиент
├── sql/                    # Миграции
├── tests/                  # e2e, integration, security, unit
├── docs/                   # Этот каталог
└── infra/                  # docker-compose, CI, k8s
```

## 5. Verification Pipeline (state machine)

```
CREATED → DIFF_READY → STRUCT_CHECK → STATIC_ANALYSIS →
DEPENDENCY_SCAN → SECRET_SCAN → BUILD_AND_TEST → SANDBOX_RUN →
RISK_ASSESS → REPORT → COMPLETED/FAILED
```

Каждая стадия получает `StageContext` (run, store, накопленные findings, meta,
deadline) и возвращает findings. Статус, длительность и ошибка сохраняются в
`CheckRun.Stages` и в audit log.

**Контракты стадий:**

- стадия обязана укладываться в `Deadline`; внешние команды ограничены
  таймаутом и лимитом вывода;
- ошибка critical-стадии немедленно завершает run со статусом `failed`;
- ошибка non-critical стадии превращается в `low` finding, run продолжается;
- пути строятся только через `safeJoin`, обход дерева ограничен;
- секреты не попадают в audit log — только путь и номер строки.

**Итоговый статус:**

- `failed`, если score < 50 или `risk_level == "critical"`;
- иначе `completed`.

Job может быть отменён; повтор только при безопасных условиях
(idempotent шаги, lock-файлы фиксации).

## 6. Соглашения

- Go API — стабильный на уровне v0; внутри v0 breaking changes запрещены.
- REST: `POST /api/v1/projects/{id}/checks`, `GET /api/v1/checks/{id}`.
- MCP: инструменты `qorvex.verify`, `qorvex.status`, `qorvex.report`.
