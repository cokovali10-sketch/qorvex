# Qorvex — Roadmap разработки

> Версия: 0.1.0
> Статус: черновик (Sprint 0)

Разработка ведётся итеративно. Каждый спринт имеет измеримый acceptance criteria.

## Sprint 0 — Архитектура и модель угроз

**Цель:** установить фундамент: типы, модель угроз, pipeline contract, тесты.

- [x] ARCHITECTURE.md
- [x] THREAT_MODEL.md
- [ ] Domain model (Go): Project, CheckRun, Finding, Diff
- [ ] Минимальный pipeline stub (no-op stages)
- [ ] Acceptance: unit tests ≥ 80%, `go test ./...` green, `go vet` clean

## Sprint 1 — Минимальный вертикальный срез (MVP pipeline)

**Цель:** исполнять один pipeline end-to-end на локальном runner без sandbox.

- [ ] CLI `qorvex check <project>` с 3-мя no-op-stage
- [ ] REST API: `/projects`, `/checks` CRUD
- [ ] Postgres schema v1 (migrations)
- [ ] Acceptance: e2e test с fake project + fake scanner, coverage ≥ 50%

## Sprint 2 — Execution Engine (Rust sandbox)

**Цель:** изолированный запуск untrusted кода.

- [ ] `qorvex-executor` (Rust): seccomp-bpf + namespaces + rlimits
- [ ] Go-ffi: `ExecutionResult` → `Finding`-map
- [ ] Acceptance: тесты на блокировку сетевого доступа, файловой изоляции;
  `cargo test` + `go test` green.

## Sprint 3 — Code Analysis Engine

**Цель:** подключаемые анализаторы (semgrep, bandit, custom).

- [ ] Python runner: `qorvex-analyzers` (pip-installable)
- [ ] JSON finding schema, severity, CWE, remediation
- [ ] Acceptance: 10+ тестов, benchmark < 5 сек/модуль.

## Sprint 4 — Dependency & SBOM

**Цель:** CycloneDX SBOM + уязвимости.

- [ ] SBOM generator (syft/spdx)
- [ ] pip-audit / cargo-audit / npm-audit adapter
- [ ] Acceptance: SBOM для sample projects, CVE detection ≥ 2 реальных.

## Sprint 5 — AI Agent Integration

**Цель:** MCP server + adapter framework.

- [ ] `mcp-qorvex` server: `qorvex.verify`, `qorvex.status`
- [ ] Adapter SDK для custom агентов
- [ ] Acceptance: handshake test с OpenCode MCP client.

## Sprint 6 — Policy Engine + Audit

**Цель:** declarative policies + immutable audlog.

- [ ] Policy DSL (YAML): `deny`, `require`, `alert`
- [ ] Policy eval в pipeline
- [ ] Immutable audit log (SQL + signature)
- [ ] Acceptance: policy violation blocks merge, audit replay возможен.

## Sprint 7 — Dashboard

**Цель:** web panel + API + аутентификация.

- [ ] React SPA: project list, check history, findings view, policy editor
- [ ] Auth: session cookies / JWT
- [ ] Acceptance: 100 e2e UI тестов, CSP + CSRF защита.

## Sprint 8 — Performance, release, docs

**Цель:** масштабирование + production hardening.

- [ ] Worker pool tuning, pipeline parallelization
- [ ] GitHub release workflow
- [ ] Acceptance: 1000 concurrent pipelines, 95-percentile < 30sec.

## Глобальные acceptance criteria

| Критерий | Порог |
|---|---|
| Unit test coverage (Go/Rust/Python) | ≥ 80% |
| Security test coverage (списки угроз) | 100% T001-T007 |
| CI: build + vet + test | green on master |
| e2e smoke test | ≤ 2 min on laptop |
