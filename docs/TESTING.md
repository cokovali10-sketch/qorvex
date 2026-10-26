# Qorvex — Стратегия тестирования

> Версия: 0.2.0
> Статус: актуально для текущего прототипа

## 1. Пирамида тестов

```
           ┌─────────────┐
           │   E2E (10%) │  CI: nightly, pre-merge
           └─────────────┘
       ┌───────────────────┐
       │  Integration (30%)│  CI: every PR
       └───────────────────┘
   ┌───────────────────────────┐
   │       Unit (60%)          │  CI: every push
   └───────────────────────────┘
```

Текущее состояние: **106 тестовых функций** в 7 Go-пакетах + **9 Python-тестов**,
все зелёные.

| Пакет | Что покрыто |
|-------|-------------|
| `pkg/platform` | domain types, JSON roundtrip, sandbox defaults |
| `pkg/store` | CRUD, конкурентный доступ, аудит |
| `pkg/policy` | правила block/warn/allow, приоритеты, frozen |
| `pkg/audit` | HMAC-подпись, verify, tamper detection, лимиты |
| `pkg/forge` | JSON-контракт Forge, severity mapping |
| `pkg/orchestrator` | path safety, bounded walk, secret rules, парсеры, риск, отчёт, fail-closed |
| `pkg/api` | health, projects, checks, policies, audit verify, CORS |

## 2. Unit (Go)

- `go test ./pkg/... -count=1 -v`
- `go test ./pkg/... -race -coverprofile=coverage.out`
- Порог покрытия: `go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//'` ≥ 80
- `go vet`, `staticcheck`, `golangci-lint run`

## 3. Unit (Rust)

- `cargo test --workspace --all-targets`
- `cargo clippy -D warnings`
- `cargo audit` (dependencies)

## 4. Unit (Python)

- `pytest -x -v --cov=qorvex_analyzers --cov-report=term-missing`
- Порог: ≥ 80%
- `ruff check .`, `mypy --strict`

## 5. Unit (TypeScript)

- `npm run test:unit -- --coverage`
- Порог: ≥ 75%
- `npm run lint`, `npm run typecheck`

## 6. Integration

- `docker-compose -f docker-compose.test.yml up --abort-on-container-exit`
- Тесты: API contract, DB migrations roundtrip, pipeline state transitions

## 7. Security (Adversarial)

Реализованные тесты (`pkg/orchestrator/stages_test.go`):

- path traversal отклоняется (`TestSafeJoin`);
- sibling-каталог с общим префиксом не считается вложенным (`TestIsWithin`);
- symlink, ведущий за пределы root, даёт `high` finding (`TestStageStructureCheckSymlinkEscape`);
- обход дерева ограничен и пропускает `.git`/`node_modules` (`TestWalkProject*`);
- файлы больше лимита не читаются (`TestReadFileBounded`);
- AWS-ключи и private keys детектируются, placeholder-значения — нет;
- команды не выполняются через shell, вывод и время ограничены.

Не реализовано (roadmap): seccomp/namespace isolation tests, fork-bomb OOM,
dependency confusion, audit replay.

## 8. E2E / Smoke

- `tests/e2e/smoke.sh`: create project → push diff → wait check → assert report

## 9. CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
jobs:
  lint-go:
    runs: go vet / staticcheck / golangci-lint
  lint-rust:
    runs: cargo clippy / cargo fmt --check
  lint-py:
    runs: ruff / mypy
  lint-ts:
    runs: eslint / tsc --noEmit
  test-unit:
    runs: go test / cargo test / pytest / vitest
  test-integration:
    runs: docker-compose integration
  test-security:
    runs: go test -tags=security ./tests/security/...
  build:
    runs: go build / cargo build --release / npm run build
  release:
    on: tag
    runs: goreleaser / cargo publish / npm publish
```

## 10. Benchmarks

- `go test -bench=. -benchtime=10s ./pkg/...`
- `cargo bench` (criterion)
- Измерения: pipeline latency, sandbox startup, scan throughput
