# Qorvex — Стратегия тестирования

> Версия: 0.1.0
> Статус: черновик

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

## 2. Unit (Go)

- `go test ./... -race -coverprofile=coverage.out`
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

- Тесты изоляции: `tests/security/isolation_test.go`
  - net access blocked
  - fs outside workspace blocked
  - secrets not leaked
  - fork bomb OOM killed
  - seccomp rules enforced

- Dependency confusion: имитация 악意 pkg

- Audit log tamper detection: подпись лога, проверка при чтении

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