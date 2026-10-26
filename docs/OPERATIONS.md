# Qorvex Operations Guide / Руководство по эксплуатации

> Version: v0.3.0 / Версия: v0.3.0  
> Language: EN / RU — bilingual / двуязычный

---

## 1. Overview / Обзор

This document describes how to operate Qorvex in production, development, and emergency modes.  
Этот документ описывает эксплуатацию Qorvex в production, development и аварийных режимах.

---

## 2. Architecture Overview / Архитектурный обзор

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│   Client    │────▶│  Go API:8420 │────▶│   Pipeline  │────▶│  Store   │
│  (React)    │◀────│  Auth/JWT    │◀────│  9 stages   │◀────│  (PG SQL)│
└─────────────┘     └──────────────┘     └─────────────┘     └──────────┘
         │                    │                     │
         ▼                    ▼                     ▼
    Dashboard            Policy Engine         Rust Sandbox
    (TypeScript)          (fail-closed)        (seccomp+ns)
         │                    │                     │
         ▼                    ▼                     ▼
     Audit Log          Secret Scan              Python
     (HMAC-SHA256)      (bandit+semgrep)         Scanners
```

---

## 3. Deployment / Развертывание

### 3.1 Docker Compose / Docker Compose
```bash
docker-compose up -d db qorvex
curl -f http://localhost:8420/health || echo "FAIL"
```

### 3.2 Kubernetes (optional / опционально)
Apply `k8s/` manifests (not included — add if needed).

---

## 4. Running Checks / Запуск проверок

### 4.1 Create Project / Создать проект
```bash
curl -X POST http://localhost:8420/api/v1/projects \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"demo","path":"/workspace/demo"}'
```

### 4.2 Start Check / Запустить проверку
```bash
curl -X POST http://localhost:8420/api/v1/projects/<id>/checks \
  -H "Authorization: Bearer $TOKEN"
```

### 4.3 Poll / Опрос
```bash
for i in {1..60}; do
  curl -s http://localhost:8420/api/v1/checks/<id> | grep '"status"';
  sleep 1;
done
```

---

## 5. Security Operations / Операции безопасности

### 5.1 Fail-Closed Check / Проверка fail-closed
If `risk_level == "critical"`, the check MUST be `failed`. Verify with:
```bash
curl -s http://localhost:8420/api/v1/checks/<id> | jq '.result.risk_level, .status'
```

### 5.2 Audit Verification / Проверка аудита
```bash
curl -s http://localhost:8420/api/v1/audit/verify | jq '.valid'
```

### 5.3 Secret Rotation / Ротация секретов
When `secret_scan` detects AWS keys or private keys:
1. Rotate key immediately / немедленно
2. Update policy / обновить политику
3. Re-run check / перезапустить проверку

---

## 6. Monitoring / Мониторинг

### 6.1 Metrics Endpoint / Метрики
- Pipeline telemetry via `pkg/telemetry/`
- Stage duration, failure counts, severity distribution
- Audit replay for investigation

### 6.2 Alert Rules / Правила оповещений
- `pipeline_failed` + `critical` → page
- `audit_verify == false` → incident
- `sandbox_violation` → security event

---

## 7. Troubleshooting / Устранение неполадок

| Symptom / Симптом | Action / Действие |
|-------------------|-------------------|
| Server not responding / Сервер не отвечает | Check `docker-compose ps`, restart `qorvex` |
| Check hangs / Проверка зависла | Verify `timeout_secs`; check sandbox resources |
| Audit invalid / Аудит невалиден | Run `/audit/verify`; check HMAC secret |
| Python import error / Ошибка Python | Check `python/scanners/` registry functions |
| Rust sandbox crash / Сбой sandbox | Check namespace/cgroup permissions; Linux only |
| TypeScript build fails / TS сборка падает | Run `npm run build`; check JWT auth |

---

## 8. Backup & Recovery / Резервное копирование

```bash
# Database backup / Бэкап БД
pg_dump -U qorvex -d qorvex > backup_$(date +%F).sql

# Config backup / Конфиг
cp -r .qorvex/ backup_config/

# Restore / Восстановление
psql -U qorvex -d qorvex < backup_YYYY-MM-DD.sql
```

---

## 9. Updates / Обновления

Always pull latest from `master` and verify tag `v0.3.0+`.  
Всегда обновляйтесь с `master` и проверяйте тег `v0.3.0+`.

---

*Document version: v0.3.0 / Версия документа: v0.3.0*