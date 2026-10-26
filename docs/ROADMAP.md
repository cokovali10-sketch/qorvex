# Qorvex — Roadmap разработки

> Версия: 0.2.0
> Статус: рабочий прототип (Sprint 0–6 частично закрыты)

Разработка ведётся итеративно. Каждый спринт имеет измеримый acceptance criteria.

## Sprint 0 — Архитектура и модель угроз

**Цель:** установить фундамент: типы, модель угроз, pipeline contract, тесты.

- [x] ARCHITECTURE.md
- [x] THREAT_MODEL.md
- [x] Domain model (Go): Project, CheckRun, Finding, Diff
- [x] Pipeline с реальными стадиями (не no-op)
- [x] Acceptance: 106 тестовых функций, `go test` green, `go vet` clean

## Sprint 1 — Минимальный вертикальный срез (MVP pipeline)

**Цель:** исполнять один pipeline end-to-end на локальном runner без sandbox.

- [ ] CLI `qorvex check <project>`
- [x] REST API: `/projects`, `/checks`, `/findings`, `/policies`, `/audit`
- [x] Postgres schema v2 (migrations 001 + 002)
- [x] Acceptance: e2e через API (создание проекта → check → отчёт)

## Sprint 2 — Execution Engine (Rust sandbox)

**Цель:** изолированный запуск untrusted кода.

- [x] Rust scaffold: конфиг sandbox, rlimits, deny-by-default
- [ ] seccomp-bpf + namespaces (Linux)
- [ ] Go-ffi: `ExecutionResult` → `Finding`-map
- [ ] Acceptance: тесты на блокировку сетевого доступа, файловой изоляции

## Sprint 3 — Code Analysis Engine

**Цель:** подключаемые анализаторы (semgrep, bandit, custom).

- [x] Python runner: `python -m scanners.cli`
- [x] JSON finding schema: severity, CWE, remediation, rule_id
- [x] Forge adapter + fallback на встроенный сканер
- [x] Acceptance: тесты парсеров и стадий, benchmark < 5 сек/модуль

## Sprint 4 — Dependency & SBOM

**Цель:** SBOM + уязвимости.

- [x] pip-audit / cargo-audit / npm-audit / govulncheck adapters
- [x] Манифесты как SBOM-сводка в отчёте
- [ ] CycloneDX SBOM (syft/spdx)
- [ ] Acceptance: CVE detection ≥ 2 реальных

## Sprint 5 — AI Agent Integration

**Цель:** MCP server + adapter framework.

- [x] Forge-Factority интеграция в pipeline
- [ ] `mcp-qorvex` server: `qorvex.verify`, `qorvex.status`
- [ ] Adapter SDK для custom агентов
- [ ] Acceptance: handshake test с OpenCode MCP client

## Sprint 6 — Policy Engine + Audit

**Цель:** declarative policies + immutable audit log.

- [x] Policy engine: `block` / `warn` / `allow`, frozen-режим
- [x] Immutable HMAC-SHA256 audit log + `/audit/verify`
- [x] Аудит всех стадий pipeline
- [ ] Policy DSL (YAML): `deny`, `require`, `alert`
- [ ] Policy eval как отдельная стадия pipeline
- [ ] Acceptance: policy violation blocks merge, audit replay возможен

## Sprint 7 — Dashboard

**Цель:** web panel + API + аутентификация.

- [x] React SPA: проекты, проверки, стадии, findings, политики, аудит
- [ ] Auth: session cookies / JWT
- [ ] Acceptance: e2e UI тесты, CSP + CSRF защита

## Sprint 8 — Performance, release, docs

**Цель:** масштабирование + production hardening.

- [ ] Worker pool tuning, pipeline parallelization
- [ ] GitHub release workflow
- [ ] Acceptance: 1000 concurrent pipelines, 95-percentile < 30sec

## Глобальные acceptance criteria

| Критерий | Порог |
|---|---|
| Unit test coverage (Go/Rust/Python) | ≥ 80% |
| Security test coverage (списки угроз) | 100% T001-T007 |
| CI: build + vet + test | green on master |
| e2e smoke test | ≤ 2 min on laptop |

