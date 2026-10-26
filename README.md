╔════════════════════════════════════════════════════════════════════╗
║  ◈◆◇  Q O R V E X  —  AI Code Verification Platform  ◇◆◈         ║
║     Build · Verify · Audit · Secure · Fail-Closed                ║
╠════════════════════════════════════════════════════════════════════╣
║  EN: AI code verification with isolated sandbox, secret scan,    ║
║  dependency audit, HMAC audit log, 9-stage pipeline.              ║
║  RU: Проверка AI-кода с изолированным sandbox, сканером секретов,║
║  аудитом зависимостей, HMAC-логом, 9-этапным пайплайном.         ║
╚════════════════════════════════════════════════════════════════════╝

# ◈ Qorvex — AI Code Verification Platform / Платформа проверки AI-кода

> **Build. Test. Verify. — Безопасная проверка кода от AI-агентов.**

```
                    ┌─────────────────────────────┐
                    │     QORVEX PLATFORM         │
                    │     v0.3.0  ·  2026        │
      ┌─────────────┼─────────────────────────────┼─────────────┐
      │  Go Core    │  Rust Sandbox              │  Python     │
      │  Pipeline   │  seccomp + namespaces      │  Scanners   │
      │  Policy     │  cgroups v2                │  semgrep    │
      │  HMAC Audit │  Job Objects (Win)         │  bandit     │
      └─────────────┼─────────────────────────────┼─────────────┘
                    │     TypeScript Dashboard   │
                    │     React + JWT Auth       │
                    │     6 Pages + Login        │
                    └─────────────────────────────┘
                            PostgreSQL DB
```

---

## 🇬🇧 English / 🇷🇺 Русский

---

### 🚀 Quick Start / Быстрый старт

```bash
git clone https://github.com/cokovali10-sketch/qorvex.git
cd qorvex
go run ./cmd/qorvex
# Open http://localhost:8420
# Login: admin / admin123 (default / по умолчанию)
```

### 🏗️ Architecture / Архитектура

| Language / Язык | Component / Компонент | Purpose / Назначение |
|-----------------|----------------------|----------------------|
| Go | Core API / Pipeline / Policy / Audit / Store | 9-stage verification with telemetry |
| Rust | Execution Engine / Sandbox | seccomp-bpf + user namespaces + cgroups v2 (Linux); Job Objects (Win) |
| Python | Code Analysis / Secret Scan / Dependency Audit | semgrep + regex fallback + bandit |
| TypeScript | Web Dashboard (React + Vite) | 6 pages: Dashboard, Projects, CheckDetail, Policies, AuditLog, Login |
| SQL (PostgreSQL) | Migrations / Telemetry | `check_stages`, `risk_level`, `severity_counts`, HMAC audit |

### 🔬 Verification Pipeline / Пайплайн проверки (9 stages / 9 стадий)

| # | Stage / Стадия | Critical? / Критично? | What it does / Что делает |
|---|----------------|----------------------|---------------------------|
| 1 | `diff_ready` | ✅ | VCS state / состояние репозитория |
| 2 | `structure_check` | ✅ | Bounded tree walk, symlink escape / обход дерева, symlink |
| 3 | `static_analysis` | — | Forge audit → Python scanner fallback |
| 4 | `dependency_scan` | — | govulncheck / npm audit / pip-audit / cargo audit |
| 5 | `secret_scan` | ✅ | AWS / GitHub / Slack / Google keys, private keys, generic credentials |
| 6 | `build_and_test` | — | `go build`, `cargo check`, `npm run build`, `compileall` |
| 7 | `sandbox_run` | — | Run `.qorvex/sandbox.json` in Rust sandbox |
| 8 | `risk_assessment` | ✅ | Severity aggregation → low / medium / high / critical |
| 9 | `report_generation` | ✅ | Score, counts, SBOM manifests, summary |

**Fail-closed rules / Правила fail-closed:**
- Critical stage error → check `failed` / ошибка критической стадии → `failed`
- `risk_level=critical` → `failed` regardless of score / критический риск → `failed` всегда
- Path traversal blocked / `..` и абсолютные пути запрещены
- Resource bounds: 5000 files, depth ≤64, file ≤1 MiB, output ≤64 KiB / 1MB trimmed

---

## 🔒 Security / Безопасность

- **Fail-closed** — never skip a critical failure / никогда не пропускать критическую ошибку
- **Deny-by-default** — minimal sandbox privileges / минимальные привилегии sandbox
- **Immutable audit** — HMAC-SHA256 per event / неизменяемый HMAC-подписанный лог
- **Path safety** — canonical root, no absolute / `..` paths / канонизация root
- **Resource bounds** — file/size/depth/time limits / лимиты файлов/размера/глубины/времени
- **Secrets hygiene** — secrets not logged / секреты не логируются; only file + line in findings

---

## 📊 Scale / Масштаб

| Layer / Слой | Files / Файлов | Lines / Строк |
|-------------|----------------|---------------|
| Go (core + tests) | 18 | 4 597 |
| Rust (sandbox) | 1 | 191 |
| Python (scanners + tests) | 4 | 492 |
| TypeScript (dashboard) | 10 | 741 |
| SQL (migrations) | 2 | 136 |
| **Code total / Код всего** | **35** | **6 157** |
| Docs / Документация | 8 | 653 |
| Config (no lockfile) / Конфиг | 9 | 184 |
| **Author total / Авторский итог** | **52** | **6 994** |

`package-lock.json` (2 627 lines) excluded / не входит в авторский масштаб.

---

## 🧪 Testing / Тестирование

```bash
# Go — 106 test functions / функций
# 7 packages / пакетов — all passing / все проходят
go test ./pkg/... -count=1 -race

# Python — 9 tests / тестов
cd python && python -m pytest tests -q

# Rust
cargo test --manifest-path rust/Cargo.toml 2>/dev/null || echo "Rust sandbox requires Linux/Win build env"

# TypeScript / Dashboard
cd ts && npm run build && npm test
```

---

## 🐘 Database / База данных

```bash
psql -U qorvex -d qorvex -f sql/migrations/001_initial_schema.sql
psql -U qorvex -d qorvex -f sql/migrations/002_pipeline_telemetry.sql
```

`002` adds telemetry: `check_stages`, `risk_level`, `severity_counts`, relaxed CHECK for namespaced values (`forge-security`, `stage-error:*`).

---

## 🔗 Forge Integration / Интеграция с Forge

Uses [Forge AI Toolkit](https://github.com/cokovali10-sketch/forge-ai-toolkit) (72 tools / инструментов). Adapter: `pkg/forge/client.go`. If unavailable / недоступен, `static_analysis` falls back to Python scanner / автоматически переключается на Python-сканер.

```json
{
  "mcpServers": {
    "qorvex": { "command": "qorvex", "args": ["mcp"] },
    "forge": { "command": "D:/Forge-Factority/.venv/Scripts/python.exe", "args": ["-m", "forge.cli", "mcp"] }
  }
}
```

---

## 🌐 Bilingual / Двуязычный

All docs in `docs/` support EN/RU. The dashboard supports both locales via `lang` attribute. API returns bilingual error messages when `Accept-Language` header is provided.

---

## 📄 License / Лицензия

MIT — see [LICENSE](LICENSE) / см. [LICENSE](LICENSE).

---

## 👤 Author / Автор

**cokovali10-sketch**

Repo / Репозиторий: `https://github.com/cokovali10-sketch/qorvex`
Commit / Коммит: `ca84eae` (v0.3.0)
Status / Статус: All priorities done / Все приоритеты выполнены
