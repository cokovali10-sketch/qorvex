# Qorvex — Security Policy

> Версия: 0.1.0

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Security fixes |

## Reporting a vulnerability

1. Прислать детали в **private security advisory** в этом репозитории (не публично).
2. Ожидаем первичный ответ в течение 72 часов.
3. Coordinated disclosure — 90 дней до публичного раскрытия.

## Threat-model quick reference

См. [docs/THREAT_MODEL.md](THREAT_MODEL.md).

## Hard guarantees платформы

- **Fail-closed:** невозможность запуска проверки = `FAILED`, а не `PASSED`.
- **Deny-by-default:** sandbox-контейнеры создаются с restrictive security profile.
- **No host secrets:** анализаторы не получают доступ к secrets окружения.
- **Policy freeze:** `frozen: true` политики нельзя редактировать пользователем с role ниже `admin`.

## Safe harbor

Тестовые payloads, созданные внутри sandbox-контейнера с фиксированным snapshot,
не рассматриваются как «вредоносный код» при тестировании продукта Qorvex.
