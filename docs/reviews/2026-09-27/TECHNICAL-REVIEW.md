# Sokol-Core: повторне рев’ю готовності до production

**Дата:** 2026-09-27. **Об'єкт:** `98b5a5df4934ef88c923a9a2959176907bfeabba`.
**Пріоритет:** production grade; адаптивність — після перевірки операційних меж.
Початковий checkout чистий. Production-файли не змінювалися; перевірки виконані на точному
Git-export і в ізольованому harness. Це focused engineering review, не сертифікація чи
вичерпний security audit. Попередні звіти залишаються історичними знімками.

## Висновок

**Це значно сильніший Pilot, але ще не production-qualified система.** Основний прогрес —
перехід від виправлення одиничних дефектів до перевірки інваріантів, походження повідомлень
і повторюваної збірки. Наступний бар'єр — поведінка при пошкодженому/повільному storage,
зміні ідентичності та конфігурації, restart і поєднанні цих подій.

Рекомендація: короткий етап стабілізації lifecycle-контрактів перед новими функціями.
Дозволяти контрольований пілот із відпрацьованим rollback; не заявляти загальну production
готовність лише за зеленим CI. Нові capabilities, федерацію й автоматичне навчання поки
не додавати на enforcement path.

## Що покращилося після бази PR #31

- **Event IDs:** адаптерні повтори в межах живого daemon не додають strike; пам'ять
  обмежена й eviction спостережуваний. Це реальне поліпшення, але не durable exactly-once.
- **Model-based property testing:** сценарії зміни таблиці, restart, retraction, quota,
  clock і fault injection; зафіксовані регресії шести знайдених дефектів. Звичайний запуск
  містить 4096 випадків із послідовностями до 59 операцій. Це bounded testing, не доведення.
- **Mesh v2:** явний wire header, підпис версії/полів, ML-DSA-65 із context separation,
  алгоритмічно позначені ключі, відмова несумісній версії. Прибрано зайвий DagTracker.
  Реально підтримується лише v2; handshake range не створює сумісності з v1.
- **Build hygiene:** toolchain закріплено датою, actions — SHA, завантаження — checksum;
  locked build/test, cargo-deny, manifest і checksums артефактів.
- **Panic policy:** заборонено низку небезпечних конструкцій Clippy; це корисний gate,
  але R27-01 показує, що його проходження не доводить відсутності panic.
- **Наявна база:** origin-only snapshots, bounded snapshot bytes, справедливий map retry,
  cumulative peer leases, durable operator decisions і defense reconciliation лишаються
  в реалізації й проходять включені тести. Старі R26 не перенесено як відкриті знахідки.

## Перевірки й межі evidence

| Перевірка | Результат |
|---|---|
| GitHub CI exact SHA | success; [run 36307428144](https://github.com/ValkyrieSentinel/sokol-core/actions/runs/36307428144), лог збережено |
| CI Linux unit tests | 156 PASS, 1 ignored (ручний benchmark seal/open) |
| CI XDP smoke | 113 рядків PASS; три-вузловий demo step теж success; це evidence чужого runner |
| Власний Linux/aarch64 контейнер, pinned toolchain | eBPF build, workspace tests: 156 PASS/1 ignored, Clippy all-targets PASS |
| Окремий production `--bin orchestrator` Clippy | PASS; Unicode panic ним не виявлений |
| Власний domain/transport/state harness | 79 PASS, 1 ignored: 74 існуючі tests + 5 review probes |
| Native NIC, production systemd, фізичний ARM, soak під навантаженням | Не перевірено; aarch64 build не є ARM/NIC qualification |
| Fresh vulnerability-advisory audit | Окремо не запускався; перевірено наявність і success CI cargo-deny |

[Harness](evidence/reproduce.py) читає pinned commit. `block_table.rs` використовує оригінальні
переходи та тестові карти; лише Aya imports перенаправлені на type stubs. `p2p.rs` оригінальний,
із доданими probes; його наявні TCP-тести використовують loopback. `save_state`/`StateStore`
витягнуто дослівно з main. eBPF map adapter у harness не виконується.

**PASS review probe означає відтворений контрприклад, не виправлення.**

```sh
python3 docs/reviews/2026-09-27/evidence/reproduce.py
```

Первісний Linux bind mount виявився порожнім у Docker daemon; це environment failure,
не build failure коду. Повтор через `git archive | docker run -i` завершився успішно.
Перший FIFO probe помилково очікував, що macOS відхилить fsync FIFO; після розблокування
операція завершилася успішно. Цю платформну гіпотезу прибрано, початковий лог збережено;
перевірка власне зависання та health лишилася незмінною.

## Знахідки

Позначення: **R** — виконаний контрприклад; **S** — простежений код, без end-to-end відтворення.
P1 — до розширення production deployment; P2 — наступний обов'язковий етап кваліфікації.
Це пріоритети робіт, не CVSS.

### R27-01 · P1 · R — невалідний Unicode-ключ викликає panic

**Код:** `orchestrator/src/p2p.rs:70–78`, `parse_public_key`; виклик із `TrustStore::load`.
`from_hex` перевіряє парність кількості байтів, а потім ріже UTF-8 рядок за двобайтовими
межами. `parse_public_key("mldsa65:a€")` панікує на межі всередині `€`.

Probe `review_non_ascii_hex_panics` ловить panic. На release `panic=abort`, отже такий
peers-файл при старті або `RELOAD_PEERS` може зупинити daemon замість `ERR` зі збереженням
попередньої конфігурації. Це локальна конфігураційна поверхня, **не** доведена атака довільного
мережевого клієнта. Clippy проходить і в CI, і в окремому production-запуску.

**Зміна:** ASCII/hex validation до декодування; працювати по bytes/chunks, повертати помилку.
**Gate:** corpus довільного UTF-8, порожні/довгі/непарні ключі; load/reload не abort,
попередній trust store і enforcement збережені. Panic lint лишити, додати негативні inputs.

### R27-02 · P1 · R+S — помилка префікса ключа може очистити чинну довіру

**Код:** `p2p.rs:279–297`; `main.rs:735–771` (`RELOAD_PEERS`). Будь-який рядок без `mldsa65:`
вважається legacy, без перевірки справжнього формату старого ключа. Для
`mldsa6S:garbage` `TrustStore::load` повертає `Ok`, позначає peer legacy й дає нуль pinned peers.

Probe `review_typo_prefix_accepted_as_legacy_and_clears_trust` починає з одного довіреного
піра й підтверджує заміну store на порожній. Production reload перед цим застосовує `set_pinned`
до таблиці, тож peer claims перестають рахуватися; відповідь — `OK ... legacy key only`.
Це не надання чужих прав: це небажане відкликання чинної довіри через typo.

**Зміна:** розрізняти валідний legacy, невідомий algorithm prefix і malformed input;
кандидат перевіряти до будь-яких мутацій. Intentional migration/degraded startup — явний
режим; reload пошкодженої конфігурації лишає last-known-good. Duplicate node IDs перевіряти
незалежно від того, чи peer був legacy.
**Gate:** typo/mixed/duplicate/legacy/empty store; негативний reload не змінює pinned set,
квоти, claims або стан чинних з'єднань.

### R27-03 · P1 · R+S — затримка state I/O зупиняє maintenance tick, health не бачить зависання

**Код:** `main.rs:808–828,843–871,2134–2146`.
State I/O виконується в `spawn_blocking`, але `persist()` очікує його без deadline;
головна ticker-гілка чекає `persist()` до продовження metrics/digest і наступного expiry tick.
Індикатор healthy стає false тільки після завершення з помилкою.

Probe `review_blocked_state_write_has_no_deadline_or_unhealthy_signal` ставить FIFO замість
тимчасового файла: blocked open утримує persist щонайменше 250 ms; dirty snapshot уже
знято, healthy=true. Після контрольованого відкриття reader задача звільняється й прибирає
свої файли. Це модель блокованого filesystem call, **не** відтворення фізичного hung disk
чи вимір production p99. Необмежене очікування простежене в коді.

**Наслідок:** фіксований XDP packet path продовжує діяти, але TTL/reconciliation і heartbeat
можуть відставати; заявлене detector RPO «≤1 s» не є жорсткою гарантією. Shutdown теж чекає
state writer. Ліміт кількості map retries не обмежує цей вид затримки.

**Зміна:** один writer із generation/ack, обмеженою/coalescing чергою, метрикою віку durable
стану; maintenance не чекає диск. Operator `OK` залежить від durable ack, із визначеним
`unknown` при deadline. Просте скасування `spawn_blocking` не зупиняє системний виклик:
потрібно зберегти single-writer ordering і визначити recovery після timeout.
**Gate:** slow/hung storage, disk-full і shutdown під навантаженням; expiry прогресує,
health стає degraded за deadline, старий snapshot не перезаписує новіший.

### R27-04 · P1 · S — пошкоджений або нечитабельний state не впливає на startup health

**Код:** `main.rs:843–847,1420–1446`; `MODE` залежить від `state_store.healthy()` і audit.
StateStore створюється healthy=true. Помилка читання або JSON restore лише логуються;
вузол продовжує роботу без durable локальних claims/lifts. Немає окремого sticky restore
failure чи підтвердження оператора для відмови від попереднього стану.

**Наслідок:** неуспішне відновлення не відрізняється в state-health від справді нового
встановлення; за здорового audit можливий MODE=NORMAL. Втрачені operator lifts можуть
дозволити пізнішому peer resync повернути знятий блок. Цей останній composite-сценарій
у цьому рев’ю не запускався; висновок про startup health — статичний.

**Зміна:** відрізняти first boot, corrupt, permission denied, incompatible schema і partial
restore; зберегти проблемні байти, сигналізувати degraded/readiness. Політику продовження
локального захисту обрати явно, не зводити рішення до універсального fail-open/fail-closed.
**Gate:** corrupted/truncated/version-mismatch/read-denied state із попереднім ban і lift;
ніякого NORMAL без обраного та перевіреного recovery outcome.

### R27-05 · P2 · R — повтор того самого event після daemon restart продовжує lease

**Код:** `block_table.rs:521–551,594–660,1186–1226`; `main.rs:1117–1144`.
Event IDs і strikes не входять у Persisted. Probe: подія `crowdsec/17` у T0 дає блок до
T0+60 s; збереження/restart у T0+50 s; та сама подія приймається як нова й дає блок до
T0+110 s. Повторення daemon+adapter рестартів може знову поновлювати lease.

Це **відоме обмеження volatile dedup, тепер виміряне**, а не заперечення працездатності
адаптерної дедуплікації в живому daemon. Документація визнає volatile memory; проте
«перший strike після restart» не гарантує незмінної абсолютної тривалості реакції.

**Зміна:** визначити freshness/expiry вихідної події та атомарну durable зв'язку event→claim,
або явно прийняти контракт replay renewal для певних джерел. Eviction лишає окреме вікно
повтору навіть із persistence; його необхідно врахувати.
**Gate:** lost ACK, daemon restart, adapter restart, lift, event-memory eviction і повтор старого
активного рішення LAPI; нова доставка не отримує нові повноваження лише через restart.

### R27-06 · P2 · R — автоматична міграція identity перезаписує попередній backup

**Код:** `p2p.rs:118–127`.
`rename(path, path + ".dilithium3.retired")` замінює наявний destination на POSIX. Probe
заздалегідь створює recovery файл, підставляє legacy-sized key і підтверджує втрату старих
байтів та створення нового 36-byte SKK2 identity. Для fresh migration тест безпомилковий;
дефект проявляється при повторній міграції/ручному rollback або вже зайнятому backup path.

**Зміна:** explicit migration command/preflight, no-clobber архів, commit point, fsync
директорії й тест recovery після кожної межі. Новий key fingerprint і coordinated peers
rollout мають бути частиною runbook. Старий executable не може використати SKK2 автоматично.
**Gate:** backup exists, create/write/fsync failure, interruption, repeated migration,
частково оновлений mesh, rollback без втрати старої ідентичності.

## Інші production gaps, без заяви про нові вразливості

- Один Ubuntu CI runner не задає support matrix kernel/NIC/systemd/ARM. Native throughput,
  корисна доступність і тривалий ресурсний профіль ще потребують окремого evidence.
- Protected host/gateway snapshot лишається стартовим. Зміна адреси, маршруту чи WireGuard
  endpoint має бути подією policy, а не вимогою перезапустити захист.
- Max connections/frame/claims — необхідні, але не повний ресурсний контракт: crypto work,
  rate admission, snapshot work, pending task age і час tick потребують вимірювання.
- Артефакти завантажуються `if: always()`: корисно для діагностики, але існування artifact
  не означає успішну кваліфікацію release. Потрібний окремий release acceptance record.
- ROADMAP досі описує частину вже реалізованого як майбутню роботу. ARCHITECTURE §16 каже,
  що negotiation немає, хоча v2 уже має range check. Його не слід називати rolling v1/v2 upgrade.
- ADR не повинні вимагати приватного контексту. Ізоляція policy/state від Linux build потрібна
  вже для звичайного reviewer; наш разовий harness не є підтримуваним product API.

## Рекомендований порядок

1. Закрити R27-01/02/06 одним перевіреним конфігураційно-міграційним циклом.
2. Окремо R27-03/04: health/readiness, durable writer, restore/rollback; не змішувати з новими
   алгоритмами реакції.
3. Узгодити та перевірити replay/freshness R27-05, включно з overflow і operator lift.
4. Кваліфікувати один deployment profile й реальний пілот; release лише за його доказами.
5. Потім розвивати «живість»: своєчасне завершення реакцій, відновлення обміну, outcome
   memory; рекомендації у shadow до будь-якого адаптивного enforcement.

Детальний план, gates і критерії зупинки: [PRODUCTION-STRATEGY.md](PRODUCTION-STRATEGY.md).
