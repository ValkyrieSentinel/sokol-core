# Sokol-Core: production roadmap

**Оновлено:** 2026-09-27. **База:** `98b5a5d`.
**Статус:** рекомендована стратегія, що потребує прийняття відповідальними за deployment.
Основний вектор — **production grade для визначеного профілю**. Другорядний — живість:
завершення реакцій, відновлення корисного обміну та пам'ять наслідків.

## Поточний стан

Pilot суттєво посилено: event IDs, model-based тести, origin-only mesh, wire v2/ML-DSA-65,
закріплений toolchain, dependency policy, build manifests, reconciliation і durable operator
state. На перевіреному SHA CI та незалежний Linux build/test проходять; це ще не native-NIC
або польова qualification. Wire v2 підтримує тільки v2, а не змішаний rolling v1/v2 mesh.

Нове [рев’ю стану](docs/reviews/2026-09-27/TECHNICAL-REVIEW.md) містить відтворені контрприклади
та межі перевірок. Повні пакети робіт і gates — у
[стратегії production](docs/reviews/2026-09-27/PRODUCTION-STRATEGY.md).

## Найближчі цикли: стабілізація

| Пакет | Результат, потрібний для завершення |
|---|---|
| P0 · RC, публічні ADR, support profile | Один SHA, відтворювані докази, визначені власники release та incident response |
| P1 · Конфігурація й identity | Unicode/malformed input не зупиняє daemon; невдалий reload лишає чинну довіру; migration не затирає recovery bytes |
| P2 · Storage і maintenance | Повільний диск не зупиняє expiry/reconciliation; corrupt restore видимий; generation/ack і shutdown мають визначений контракт |
| P3 · Replay та мережеві зміни | Restart не поновлює reaction lifetime неявно; bounded outbox/freshness; protected адреси й шлюзи оновлюються |
| P4 · Один deployment profile і пілот | Native NIC/ресурси/корисна доступність/rollback перевірені за наперед погодженими порогами |

Орієнтир — 1–3 місяці до кваліфікації одного профілю за наявності людей та обладнання;
не обіцянка дати. P1/P2 мають пріоритет перед розширенням функціоналу. Hardware й пілот
готуються паралельно; enforcement rollout чекає на відповідні gates.

## Після qualification: живість без розширення влади за замовчуванням

- Зв'язати event → decision → applied outcome → expiry/lift → observed benefit/harm/unknown.
- Вибрані рішення й відмови експортувати для зовнішньої перевірки; кандидат — Warrant sidecar.
- Малі Stargate-моделі мають контртраси, перенесені в тести реалізації.
- Адаптація TTL/порогів: спершу shadow, потім лише погоджений canary із budget та rollback.
- Федерація й переносні Sigma-Glyph checks — за підтвердженої потреби, після локальної
  production qualification. Автоматика не змінює власні trust roots чи protected set.

## Release та відповідальність

Merge, зелений CI і наявність artifact не дорівнюють прийнятому release. Потрібні точний
SHA, свіжий review, failure/recovery evidence, support profile, відповідальний оператор і
перевірений rollback. Native/generic, ARM/x86 та різні kernels кваліфікуються окремо.

За власниками: оператор першого пілоту, допустимі SLO/RPO/RTO і шкода false positive,
політика evidence/даних, ліцензія й підтримка, прийняття нових повноважень. До цих рішень
можна завершувати технічну стабілізацію та лабораторні перевірки.
