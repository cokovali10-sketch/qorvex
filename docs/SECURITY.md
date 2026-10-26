# Qorvex — Security Policy

> Версия: 0.2.0

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Security fixes |

## Reporting a vulnerability

1. Прислать детали в **private security advisory** в этом репозитории (не публично).
2. Ожидаем первичный ответ в течение 72 часов.
3. Coordinated disclosure — 90 дней до публичного раскрытия.

## Threat-model quick reference

См. [docs/THREAT_MODEL.md](THREAT_MODEL.md).

## Hard guarantees платформы

- **Fail-closed:** ошибка critical-стадии или `risk_level=critical` = `FAILED`,
  а не `PASSED`.
- **Deny-by-default:** sandbox-конфигурация по умолчанию запрещает сеть,
  read-only FS и ограничивает память/процессы/файлы.
- **Minimal environment:** внешние анализаторы получают только PATH и
  платформенные переменные; секреты родительского процесса не пробрасываются.
- **Path containment:** все пути канонизируются, absolute/`..`/symlink escape
  отклоняются.
- **Immutable audit:** HMAC-SHA256 по каждому событию, проверка через
  `/api/v1/audit/verify`.
- **Policy freeze:** флаг `frozen` сохраняется в модели политики; ролевой
  enforcement (admin-only edit) — в roadmap, до его появления не считать
  frozen-политику защищённой от записи через API.

## Safe harbor

Тестовые payloads, созданные внутри sandbox-контейнера с фиксированным snapshot,
не рассматриваются как «вредоносный код» при тестировании продукта Qorvex.
