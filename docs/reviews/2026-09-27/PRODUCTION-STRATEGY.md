# Стратегія: production grade перед адаптивністю

**База:** `98b5a5df4934ef88c923a9a2959176907bfeabba`, 2026-09-27.
**Статус:** рекомендований порядок робіт; не прийняте командою release-рішення.
[Технічне обґрунтування та перевірки](TECHNICAL-REVIEW.md).

## Напрям

Sokol має стати передбачуваним enforcement-компонентом із визначеною ціною відмови.
«Production grade» означає кваліфікацію конкретного профілю розгортання, а не безумовну
властивість усього коду. Корисний продукт — захищений сервіс, який доступний легітимному
користувачу, а не максимальна кількість блокувань.

На найближчий цикл рекомендовано приблизно **80% зусиль на correctness, recovery,
експлуатацію й вимірювання; 20% — на observability, replay та моделі, що підтримують їх**.
Автономна зміна policy не входить у цей другий бюджет. Це пропозиція розподілу роботи,
не оцінка фактичної спроможності команди.

## Послідовність пакетів

| Пакет | Орієнтовне вікно* | Залежності | Результат |
|---|---|---|---|
| P0: зафіксувати релізний кандидат | Перші 2–3 робочі дні | Немає | Один SHA, межі підтримки, реєстр доказів і відомих ризиків |
| P1: конфігурація та ідентичність | Перший цикл, орієнтовно 1–2 тижні | P0 | Некоректний reload не руйнує чинний стан; міграція й rollback відтворювані |
| P2: durable state і maintenance | Наступні 2–4 тижні | P0; інтеграція з P1 | Повільний диск не зупиняє expiry; restore outcome видимий |
| P3: delivery/freshness і динамічні захищені цілі | Наступний цикл | P2 | Повтор/перезапуск не поновлює реакцію неявно; мережеві зміни враховуються |
| P4: кваліфікація одного deployment | Паралельна підготовка; 1–3 місяці загалом | P1–P3 для enforcement | Відтворений soak, rollback і один контрольований пілот |
| L1: пам'ять наслідків і shadow-пропозиції | Після P4, горизонт 3–6 місяців | Експлуатаційний baseline | Вимірювана користь рекомендацій без нової автоматичної влади |

\* Планувальні вікна за наявності відповідальних та обладнання. Якщо gate не виконано,
пакет лишається відкритим; календар не замінює evidence.

## P0. Один кандидат, один контракт підтримки

1. Зафіксувати RC SHA й заборонити включення нерелевантних фіч у цей кандидат. Подальші
   виправлення мають новий SHA й власну повторну кваліфікацію залежних сценаріїв.
2. Призначити implementation owner, reviewer і pilot operator. Відповідальні ролі не
   обов'язково три нові посади, але самоперевірка має бути позначена як самоперевірка.
3. Опублікувати підтримуваний профіль: distro/kernel, arch, NIC/driver/XDP mode, число nodes,
   topology, detector versions, workload envelope, часова синхронізація й filesystem.
4. Перенести короткі нормативні ADR у публічний `docs/adr/`: authority, lease, event freshness,
   persistence/restore, versioning/migration, degraded modes. Замінити суперечливі status-тексти.
5. Завести release record: source/binary/config/model IDs, checksums, CI run, raw tests,
   limitations, рішення про прийняття. Діагностичний artifact невдалого CI не є release.

**Gate:** інший reviewer відтворює source-to-result зв'язок, бачить відомі R27 та може
пояснити межі гарантій без приватних записок. Бінарник має доступний version/build ID.

## P1. Конфігурація й identity — транзакційні зміни

Закрити R27-01/02/06. Зміни розділити на малі PR: строгі parsers; candidate validation та
atomic reload; explicit migration і no-clobber backup. Перевірка конфігурації не повинна
створювати нову identity або змінювати trust як побічний ефект.

Потрібний upgrade runbook для v1→v2: інвентар старих ключів, створення/поширення нових
fingerprints, порядок перемикання вузлів, допустиме вікно mesh-disconnection, local protection,
критерій rollback. v2-only range handshake сам по собі не дозволяє змішаному mesh обмінюватися
командами. Rollback має включати binary, key, peers config і state schema разом.

**Gate:** malformed Unicode/key prefix, duplicate IDs, legacy+new, частковий rollout,
existing backup, crash на межах файлових операцій. Невдалий reload зберігає last-known-good
і не змінює діючі peer claims. Дані recovery не перезаписуються.

## P2. Maintenance має прогресувати незалежно від диска

Закрити R27-03/04; окремим рішенням версіонувати durable state.

- Один state writer із generation IDs, bounded/coalescing queue і durable acknowledgements.
  Зняття snapshot не є завершенням запису. Уникнути unbounded накопичення `spawn_blocking`.
- Ticker, expiry, defense reconciliation й health не очікують filesystem call. Operator
  отримує `durable` тільки після належного ack; timeout означає визначений `unknown`,
  із можливістю перевірити outcome за operation ID.
- Restore розрізняє fresh installation, compatible state, corrupted, incompatible та
  permission denied. Пошкоджені bytes зберігаються; готовність вузла не стає NORMAL мовчки.
- Визначити terminating state: хто завершує IPC/mesh tasks, дедлайн shutdown, незавершені
  operator requests, остаточний audit/state outcome і очікувану поведінку systemd restart.
- На startup і migration перевіряти regular file/symlink policy, bounds/schema та owner/permissions
  state/key/config. Це прості операційні контракти, не новий механізм consensus.

**Метрики:** age останнього durable generation; dirty age; write duration/error/timeout;
restore status; tick lag; найстаріший pending map operation; кількість втрачених audit records.
Не достатньо одного `healthy=1`.

**Gate:** керований slow write та hung write, disk-full, corrupt state, abrupt exit, restart,
clock step; tick і expiry зберігають прогрес. Deadlines фіксуються до тесту. Перевірити
порядок запису після timeout: background syscall може завершитися пізніше.

## P3. Подія, реакція і кінець її повноважень

Закрити R27-05 й завершити delivery-контракт:

- Атомарна зв'язка event ID → decision/claim → outcome або інший явно прийнятий freshness
  контракт джерела. Повтор старої події не отримує новий lifetime за рахунок restart.
- Durable adapter outbox лише там, де вона потрібна; квоти, max age, stale outcome, метрики
  overflow. Нескінченне повторення застарілого сигналу не є надійністю доставки.
- Dedup eviction, source identity й повтор ID з іншим payload мають визначені наслідки.
  Строк зберігання marker має бути узгоджений із можливим replay горизонтом джерела.
- Host/gateway/WireGuard changes оновлюють protected set із контрольованим transition;
  втрата netlink watcher має бути видима. Для нової захищеної цілі reconcile прибирає
  несумісне застосування, а не лише відхиляє майбутні заявки.

**Gate:** lost ACK→adapter restart→daemon restart→replay→lift→resync→expiry; переповнення
пам'яті та черги; зміна маршруту під чинним блокуванням. Перевіряється наступна операція
після відмови, а не тільки факт записаного error.

## P4. Release qualification на одному профілі

Почати з 3–10 nodes однієї організації та повного mesh. До запуску погодити з оператором
числові SLO/budgets, workload і спосіб emergency rollback. Не призначати довільний універсальний
пороговий p99 лише тому, що він гарно виглядає.

| Властивість | Перевірка | Критерій прийняття |
|---|---|---|
| Корисна доступність | Контрольні легітимні транзакції з/без атаки | Узгоджений success/latency budget; protected targets не блокуються в корпусі |
| Реакція | Signal→decision→map→packet witness | Окремі p50/p95/p99, timeout і failed attempts у знаменнику |
| Завершення реакції | Expiry/lift/strict-mode exit під навантаженням | Погоджений deadline, без starvation |
| Ресурси | Тривалий steady-state та bursts до admission limit | Обмежені RSS, disk, tasks, queues; drift пояснений |
| Меш | Loss/jitter/partition/slow authenticated peer | Локальна працездатність; збіжність після heal у визначеному профілі |
| Оновлення | Canary, half-upgrade, rollback, reboot | Відновлено погоджений стан і керованість |
| Експлуатація | Інший оператор за runbook | Install, diagnose, revoke, restore без автора поруч |

Практична ціль першого soak — щонайменше 72 години на обраному профілі, з failure injection
і recovery; тривалість збільшувати за спостережуваними хвостами/циклом експлуатації. Це
запропонований мінімум evidence, не математична гарантія й не вже виконаний тест.

Перед зовнішнім enforcement: shadow збір, потім вузький canary, потім обмежений fleet rollout.
Окремо кваліфікувати native NIC, generic fallback, ARM і мінімальний підтримуваний kernel.
При дефекті authority, втраченому lift, незавершеній реакції поза deadline або непоясненому
погіршенні легітимної доступності — зупинити розширення rollout, зберегти evidence, виконати
узгоджений rollback. Рішення про universal fail-open тут не приймається.

**Release gate:** P1–P3 accepted, пороги P4 виконані, точний release SHA перевірений свіжим
reviewer із контрприкладами, support/incident owner визначений. Merge і artifacts цього не замінюють.

## Другорядний напрям: живість як перевірні властивості

На цьому етапі «живість» означає homeostasis: система встигає завершити реакцію, зберігає
корисний обмін, локально працює при partition і чесно показує свої обмеження.

1. **Спостерігати:** пов'язати event, decision, applied outcome, lease end, lift і доступність.
   Розрізняти observed benefit, observed harm, unknown. Drop counter не вимірює користь сам.
2. **Пам'ятати:** після стабілізації schema додати Warrant-exporter для вибраних consequential
   decisions і відмов. Відсутність exporter не зупиняє maintenance; record не видається за
   доказ фактичного виконання без окремого свідка.
3. **Моделювати:** Stargate для вузьких ACK/restart/revocation/expiry автоматів із контртрасами,
   які стають runtime tests. Не приймати сертифікат моделі за доказ відповідності всього коду.
4. **Пропонувати:** зміна TTL/порогів лише у shadow; порівняння зі статичною baseline за
   однакового workload, урахування невизначеності й adversarial inputs.
5. **Діяти обмежено:** лише після доведеної користі у пілоті, через окреме прийняття scope,
   budgets, expiry й rollback. Автоматика не змінює trust roots, protected set або власні
   повноваження. Sigma-Glyph — опція для реальної потреби portable replay, не обов'язкова фіча.

Довгострокова федерація відкривається лише за реального запиту кількох операторів, із
origin authority і локальним правом відмови. Вона не має бути способом обійти незакриті
ресурсні та операційні межі поточного повного mesh.

## Культура змін і «охолодження» модулів

Кожен PR змінює один контракт або одну групу тісно пов'язаних failure transitions; містить
before/after сценарій, негативний контроль, незмінні властивості, deployment risk і rollback.
Після merge перевіряється інтегрований head. Автор і reviewer не підміняють один одного
позначкою «всі тести зелені».

Кандидат на стабілізацію — модуль із явними inputs/effects, вузьким API, перевіреними failure
outcomes і визначеною сумісністю. Низький churn сам по собі нічого не доводить. Pure helpers
можна стабілізувати раніше за I/O adapters; freeze стосується версії контракту, не заборони
виправляти дефекти.

Готові аналізатори використовувати для inventory/dependencies/API rules; власні бейджі —
тільки як представлення evidence. Не запускати паралельне будівництво універсального
аналізатора, нового detector, BGP-стека чи великої fleet-консолі замість P1–P4.
