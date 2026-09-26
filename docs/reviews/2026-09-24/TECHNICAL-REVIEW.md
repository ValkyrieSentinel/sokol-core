# Sokol-Core: глибоке технічне рев’ю та план інженерного посилення

Дата: 2026-09-24. Об’єкт: `ValkyrieSentinel/sokol-core`.

**Перевірений commit:** `4cbb478e6df358d7581b6e1d50ce67d530280d50`. Початкове робоче дерево чисте. Висновки стосуються цього локального snapshot; актуальний remote HEAD, результати GitHub CI, налаштування branch protection і реальні deployments не перевірялися. Продуктовий код під час рев’ю не змінювався.

## 1. Висновок

**Рекомендація: залишити статус Pilot / Active Testing. До розширення автономного застосування блокувань закрити P1 нижче, відтворити їх на Linux і пройти незалежне рев’ю точного виправленого commit.** Наявний код є корисною основою системи enforcement, але ще не забезпечує достовірну відповідність між прийнятим рішенням, станом kernel-мап, станом upstream-маршрутизатора та повідомленням операторові.

Найважливіше покращення — визначити й реалізувати модель станів та відмов. Нова криптографія, додатковий AI чи нові detector integrations зараз дадуть менше користі, ніж гарантоване відновлення після невдалого map update, втрати доставки, перезапуску GoBGP та помилки запису аудиту.

Сильні сторони, які варто зберегти:

- Pinning mesh-ключів, підпис sender/timestamp/nonce/payload, прив’язка connection до identity, часовий replay window, ротація trust store.
- Єдина політика protected addresses для основних шляхів orchestrator, перевірка перекриття CIDR, обмеження ширини префікса.
- Розділені IPC для detector і control socket для оператора; токен на HTTP API; unsupported операції повертають помилку.
- TTL, обмежені черги для частини каналів, бюджет ring-buffer подій, backoff з’єднань, відокремлення FastNetMon victim від адреси для блокування.
- Реальний audit chain, перевірка torn tail, smoke/demo з Linux namespaces, WireGuard, GoBGP та detector adapters. Це значно сильніше за наявність лише unit-тестів.
- README прямо обмежує benchmark generic XDP і чесно описує відсутність encryption у власному mesh transport.

Це оцінка технічних артефактів. Висновків про здібності, мотивацію чи особисту культуру авторів із коду зробити не можна. Рекомендації щодо культури нижче стосуються процесів і критеріїв прийняття змін.

## 2. Метод, відтворення та межі доказів

Прочитано основні runtime-шляхи XDP, block policy/table, mesh transport/sync, audit writer/reader, Flowspec, IPC, operator dashboard, detector adapters; переглянуто client, trap, metrics, math/AI, CI, systemd, smoke/demo й benchmark scripts. Репозиторій містить 50 tracked files; reviewed Rust/smoke поверхня приблизно 11,8 тис. рядків разом із тестами. Це ручне архітектурне й correctness/security-oriented рев’ю, **не вичерпна сертифікація безпеки**.

Середовище: macOS/Darwin arm64; `rustc 1.100.0-nightly (6bb1652a0 2026-09-22)`.

| Перевірка | Результат і точна межа |
|---|---|
| `cargo fmt --all --check` | PASS |
| `cargo fmt --manifest-path ebpf/Cargo.toml --check` | PASS |
| `cargo test -p common -p sokol_ai --locked` | PASS: common — 13 тестів; AI — 0 тестів; doc tests — 0 |
| `cargo test --workspace --locked` | BLOCKED на macOS: Aya 0.12.0 потребує Linux syscall/constants (`SYS_bpf`, `SYS_perf_event_open`, `CLOCK_BOOTTIME`). Це не доказ несправності Linux build |
| Ізольований review harness | PASS: 54 тести (48 наявних + 6 review probes). Див. [повний журнал](evidence/probe-results.txt); це isolated harness, не повний workspace test |
| Linux verifier, XDP attach, namespace smoke/demo, BGP session, real NIC | Не запускалися в цьому рев’ю |
| CVE/advisory scan, fuzz campaign, crash/power-loss campaign, performance campaign | Не виконувалися; відсутність відомих вразливостей не засвідчується |

Команда відтворення з кореня репозиторію:

```sh
python3 docs/reviews/2026-09-24/evidence/reproduce.py
```

Harness створює окремий тимчасовий Cargo project. Для `block_table.rs` змінюються лише imports Aya на mock із контрольованими помилками map I/O; алгоритми `BlockTable` і `ExpiryTracker` залишаються вихідними. Mock доводить порядок переходів за умови syscall error, але не відтворює Linux errno чи kernel memory pressure. `flowspec.rs`, `p2p.rs`, portable binaries та `common` використовуються з вихідного дерева. Declarations mesh command витягуються з `mesh_sync.rs`; telemetry orchestration цим не перевіряється.

[SHA-256 джерел](evidence/source-hashes.json), [скрипт](evidence/reproduce.py), [lockfile harness](evidence/harness-Cargo.lock). PASS контрприкладу означає, що небажана поведінка **відтворилася**, а не що систему виправлено. Harness не є заміною production regression tests. Після виправлень assertions треба інвертувати й перенести до штатних тестів.

Класи доказів: **R** — виконане відтворення; **S** — підтверджений статичний шлях; **V** — гіпотеза/ризик, що потребує окремої перевірки. P1 означає пріоритет до розширення deployment; P2 — наступний етап надійності. Це пріоритети інженерної роботи, не CVSS.

## 3. Пріоритетні знахідки

### F01 — P1 / R: невдалий BlockSync залишає «фантомний» активний блок

**Джерело:** `orchestrator/src/block_table.rs:402–415`; виклик — `orchestrator/src/main.rs:894–932`.

`insert_until` спочатку викликає `expiry.record_until`, а потім записує kernel map. Якщо insert повертає помилку, tracker уже вважає адресу активною. Наступний snapshot для цієї адреси отримує `new == false` і взагалі не повторює map insert.

Контрприклад `failed_sync_poison_prevents_retry`: перша вставка помилкова, `active() == 1`, mock map порожня; після зняття fault друга синхронізація повертає `Ok(false)`, кількість спроб вставки залишається 1. Реалістичний trigger — capacity або інша помилка map update. Фантомний запис також потрапляє до `active_ips`, отже може бути анонсований через Flowspec або переданий іншому peer, хоча локально drop відсутній.

**Виправлення:** commit tracker лише після успішної вставки; або явні `desired/pending/applied` стани з retry. Оновлення existing TTL не повинно приховувати відсутній applied entry.

**Прийняття:** fail-once insert → повтор успішний → kernel lookup підтверджує drop → metrics/audit містять applied тільки після цього. Окремий Linux тест map-at-capacity → звільнення slot → повторний sync.

### F02 — P1 / R: помилка видалення втрачає блок із керування, але залишає його в kernel map

**Джерело:** `block_table.rs:321–353,379–392`; повідомлення про expiry — `main.rs:1388–1392`.

`remove_dynamic`, `remove`, `flush_dynamic`, `expire` змінюють tracker до kernel removal. У bulk-операціях помилку лише логують, а адреси повертають як released. Наступний expiry вже не бачить pending removal. Основний цикл пише «traffic allowed again», хоча drop може залишатися.

`failed_expiry_is_reported_as_removed_and_not_retried` відтворює `active() == 0` при одному entry у mock map і відсутність повтору після усунення fault.

**Виправлення:** видаляти applied state лише після успіху; `not found` обробляти окремо як ідемпотентний успіх, інші errors залишати pending. Bulk result повинен містити succeeded/failed targets. Не використовувати одну множину як desired state і як підтверджений kernel state.

**Прийняття:** inject remove fault у expiry, explicit unban і flush; жодного false-success; повтор очищає map; на Linux packet probe підтверджує відновлення проходження трафіку.

### F03 — P1 / R+S: Flowspec reconciler не звіряється з фактичним RIB

**Джерело:** `orchestrator/src/flowspec.rs:64–95`; `main.rs:1374,1464–1482,1527–1542`.

`announced` — volatile HashSet того, що цей процес колись успішно додав. Команд читання RIB немає.

1. Orchestrator падає після announce; gobgpd продовжує працювати. Новий процес має порожній `announced` і не знає, що треба відкликати старий discard.
2. Gobgpd втрачає RIB, orchestrator продовжує працювати. `announced` містить адресу; desired set той самий; нового announce немає.
3. Graceful shutdown припиняє withdrawal після першої помилки; intent на наступний запуск не зберігається.

Два tests `flowspec_forgets_surviving_rules_on_restart` і `flowspec_does_not_notice_daemon_losing_rib` підтверджують поведінку реального planner. Справжній restart двох процесів з BGP peer тут не виконувався.

**Виправлення:** спостереження actual RIB + durable intent + позначення ownership rules. Реконсиляція має порівнювати desired із observed, обробляти reconnect/restart. Не видаляти чужі правила. Визначити, чи дозволена спільна GoBGP instance і як розрізняється ownership однакового NLRI.

**Прийняття:** окремо SIGKILL orchestrator, restart gobgpd, недоступний gobgpd під час shutdown, shared daemon із foreign rule; після відновлення лише власні rules сходяться до desired state у визначений SLO.

### F04 — P1 / R+S: timeout GoBGP не зупиняє процес; slow GoBGP затримує expiry і shutdown

**Джерело:** `flowspec.rs:45–61`; `main.rs:1377–1482,1489`.

`timeout(5s, Command::output())` не задає `kill_on_drop`. Контрприклад `timed_out_gobgp_process_continues` запускає нешкідливий child (`sleep 6; touch <temporary marker>`): API повертає timeout, але marker з’являється пізніше. Семантика відповідає [документації Tokio Command](https://docs.rs/tokio/latest/tokio/process/struct.Command.html#method.kill_on_drop).

Окремо до 64 операцій виконуються послідовно всередині tick branch. При першій timeout-помилці цикл обривається, тому цей сценарій затримує tick приблизно на 5 секунд; **320 секунд timeout-помилок підряд у одному tick тут немає**. Але 64 успішні операції тривалістю майже 5 секунд кожна можуть затримати tick приблизно до 320 секунд. У цей час наступна expiry sweep, metrics publication і обробка shutdown цією loop відкладаються. Потім `dt = 1.0` спотворює rate/anomaly logs.

**Виправлення:** виділити Flowspec worker з обмеженим work/time budget, cancellation і контрольованим process lifecycle (kill + wait, за потреби process group). Використовувати виміряний monotonic elapsed. Timeout операції трактувати як uncertain outcome, після нього читати RIB.

**Прийняття:** delayed child не залишає side effect після cancellation; завислий/повільний GoBGP не порушує TTL/heartbeat/shutdown SLO; після ambiguous response виконано readback.

### F05 — P1 / S: переповнення peer queue губить block без обов’язкового відновлення

**Джерело:** `p2p.rs:515–540`; `main.rs:793–827`.

`broadcast` використовує `try_send`, логуючи full queue, і повертає `Ok(())`. BlockSync запускається на peer-up. Full queue сама собою не закриває connection і не запускає resync. Peer може наздогнати writer, залишитись підключеним та назавжди пропустити конкретний block до іншої події, що повторить його.

Наявний `broadcast_does_not_wait_for_a_stuck_peer` правильно перевіряє non-blocking поведінку, але не eventual delivery. Це **не вимога блокувати всіх заради повільного peer**: потрібне контрольоване відновлення після пропуску.

**Виправлення:** bounded per-peer dirty state із reconciliation; або sequence/ack/resend; або disconnect при overflow і гарантований snapshot на reconnect. Вибір зафіксувати в protocol ADR. Для unblock потрібні revisions/tombstones або чітка lease semantics — лише snapshot активних блоків не передає історію відкликань.

**Прийняття:** переповнити queue на живому connection, пропустити block/unblock, відновити drain без нового detector alert; усі peers збігаються в обмежений час. Перевірити dropped snapshot chunk і reconnect під час sync.

### F06 — P1 / S: IPv6 parser error обходить вже знайдений blocklist hit

**Джерело:** `ebpf/src/main.rs:191–195,199–246,399–418`.

IPv6 branch читає source і знаходить `is_blocked`, але до перевірки цього flag викликає `parse_v6_next_header(...)?`. Обрізаний extension header повертає `Err`, top-level handler перетворює його на `XDP_PASS`. Таким чином malformed IPv6 packet із заблокованим source проходить у Linux stack; цей шлях також оминає звичайний `record_rx`/`record_drop`.

Мінімальний stimulus для Linux packet test: Ethernet + повний IPv6 header із заблокованим source, next-header=Hop-by-Hop, без достатніх байтів extension header. **Це не доводить доставку валідного payload застосунку**: Linux може відкинути пакет далі. Підтверджений статичний дефект — порушення XDP block invariant і неповний облік таких пакетів.

**Виправлення:** source block precedence перед L4/extension parsing; parser errors мають явний action/reason відповідно до документованої політики. Окремо визначити поведінку для понад чотирьох extension headers, AH, fragments, truncation, VLAN depth та невідповідності IP length/frame length.

**Прийняття:** packet corpus через `BPF_PROG_TEST_RUN`/еквівалент і netns; для підтримуваних L2/L3 envelope кожен blocked source дропиться незалежно від помилки L4; bounded parsing і правильні counters. Тут виконання BPF не проведено.

### F07 — P1 / R+S: аудит не забезпечує заявленої межі durability та однозначного single writer

**Джерело:** `main.rs:43–124`; `common/src/audit_log.rs:309–330,403–440`.

- `recv_timeout(100ms)` — timeout очікування наступної події, а не periodic fsync deadline. Якщо подія приходить кожні 90ms, timeout не настане; sync відбудеться після 64 записів, приблизно через 5,7 секунди. Коментар «crash loses at most that window» не доводить 100ms RPO під безперервним помірним навантаженням.
- Flush ack надсилається навіть після fsync error; return type не передає помилку. Саме `send(Flush)` може блокувати до початку `recv_timeout(wait)` — параметр wait не обмежує всю операцію.
- `AuditLog::open_with` не має exclusive lock. `two_audit_writers_corrupt_chain` відкриває один файл двічі, обидва writers append успішно, а `verify_chain` потім виявляє пошкодження sequence. Це локальна операційна колізія, не remote exploit.
- Після часткового `write_all` error продовження append потребує recovery або переходу writer у failed state; зараз writer логуючи помилку продовжує обробку. ENOSPC/partial write не інжектувалися в цьому рев’ю.

**Виправлення:** deadline від `last_successful_sync`, exclusive file/process lock, typed `Result` flush ack, bounded enqueue deadline, health state writer. Визначити policy при недоступному audit: enforcement може продовжуватись лише з явним degraded status і loss counters, або частина змін відмовляється — це операторське продуктове рішення.

**Прийняття:** записи кожні 90ms + перевірка sync deadline; ENOSPC/EIO/partial write; подвійний запуск; завислий диск; SIGTERM під навантаженням. External checkpoint потрібен для виявлення переписаного chain; сам BLAKE3 chain не є доказом повноти або автентичності всіх історичних подій.

### F08 — P2 / S: dashboard тримає власну неавторитетну копію bans і health

**Джерело:** `sokol-operator.rs:265–296,360–414`.

Після нового heartbeat dashboard створює порожній `blacklist`; він поповнюється лише через успішні HTTP mutations цього процесу. Restart dashboard стирає список, тоді як orchestrator permanent bans залишаються. `Flush` перебирає цей локальний список і потім викликає dynamic-only flush. Отже старі operator bans можуть залишитися, хоча користувач натиснув flush.

`HEALTHY`/`xdp_loaded=true` виставляються на heartbeat, без deadline переходу до stale і без actual XDP state. Список nodes також не має expiry у цьому шляху.

**Виправлення:** read/query endpoint у daemon із типом owner (`static-config/operator/detector/peer`), applied state і revision. Flush реалізувати однією командою daemon з явним scope та частковими результатами. UI показує observed state, timestamp, stale/degraded.

**Прийняття:** ban → restart dashboard → list/flush; зміни іншим оператором; node shutdown → stale; частковий failure під час flush. Не перетворювати UI HashSet на друге джерело істини.

### F09 — P2 / S: detector delivery втрачає рішення при outage orchestrator

**Джерело:** `sokol-crowdsec.rs:180–209`; `sokol-suricata.rs:270–293`.

CrowdSec перемикає `startup=false` після успішного отримання batch, до успіху відправлення сигналів. Невідправлені записи не зберігаються й не повторюються локально. Наступні polls запитують changes, тому missed startup batch не відновлюється самим adapter. Наслідок залежить також від семантики конкретного LAPI server; її live перевірки тут не було.

Suricata читає вперед, gate відмічає IP перед send, а після failure alert явно lost. Навіть успішний Unix socket write не є application ACK про застосування block.

**Виправлення:** bounded outbox, event ID, прийняття ACK із результатом (`applied/refused/retryable`), retry policy, reconciliation active decisions. Визначити очікувану TTL semantics CrowdSec: зараз duration потрапляє в reason, але enforcement живе за Sokol TTL; це документований вибір, який потрібно узгодити з оператором.

**Прийняття:** daemon down на першому batch; daemon restart між write і apply; повтор без TTL escalation; protected refusal не повторюється безкінечно; backlog quota й observability для lost/deferred.

### F10 — P2 / S: benchmarks можуть видавати недоведені успішні результати

**Джерело:** `bench/local.sh:5–7,57–76,87–103`.

Fill/expiry polling має обмежену кількість ітерацій, але після timeout не перевіряє postcondition і все одно друкує підсумки «all … in the kernel map» / «all expired». Gauge читає tracker, не kernel map; F01/F02 роблять таке ототожнення особливо небезпечним.

Latency mode використовує час останньої echo reply як оцінку drop onset. Без прив’язки packet send/receive і наступного контрольованого probe відсутність reply може бути unrelated packet loss; твердження «0 = block within one 2ms interval» не випливає лише з останньої відповіді. Це не надійна upper bound для застосування правила.

**Виправлення:** fail при недосягнутій postcondition; незалежний map lookup/packet witness; видимі timeout/unknown samples; paired allowed-source control; timestamps event admission, map syscall completion і packet observation. Зберігати сирі samples і середовище замість видалення всього WORK у cleanup.

**Прийняття:** навмисно зламати apply/expiry; benchmark мусить завершитися nonzero. Контроль із випадковою втратою пакетів не повинен створювати fake success. Generic XDP control latency і native NIC throughput звітувати окремо.

### F11 — P2 / S: control IPC і telemetry мають прогалини в resource/identity contracts

**Джерело:** `main.rs:1076–1114,1128–1154`; `sokol-operator.rs:207–231,271–294`.

IPC/control accept loops створюють task на connection без semaphore та idle timeout. Доступ обмежений socket permissions, тому це ризик від локального authorized/compromised producer, а не доведений unauthenticated network DoS.

Operator telemetry читає лише один `read(8192)`, а stream protocol не гарантує отримання повного heartbeat за один read. У socket listener немає explicit permission setup/peer credential validation; фактичний доступ залежить від umask/каталогу. Поле `CTL=` із telemetry визначає control socket для наступної operator mutation. Це потребує окремої identity binding: ingest telemetry сам по собі не повинен визначати administrative routing.

**Виправлення:** framed bounded messages, timeout/semaphore, явні uid/gid і права socket; configured node→control endpoint registry або перевірена registration identity. Обмежити число nodes та pending peer-up notifications (останній канал зараз unbounded).

**Прийняття:** heartbeat split на довільних byte boundaries; slow local writer; connections до quota; telemetry від неправильного uid не змінює routing. Перед оголошенням security severity відтворити deployment permissions — права конкретного запущеного socket тут не перевірялися.

### F12 — P2 / S: журнал може заявити enforcement навіть після refusal

**Джерело:** `main.rs:454–526,1017–1039`.

`enforce_block_local` повертає `()`: protected refusal або failed kernel insert не відрізняються для caller від успіху. Trap caller після нього безумовно append-ить `TRAP_HIT|...|Action:EnforcedDrop`. Отже audit може одночасно містити refusal та заяву про enforced drop для тієї самої події.

**Виправлення:** повертати `EnforcementOutcome` з `Applied/Refused/Failed/Pending` і shared correlation ID; event construction залежить від результату. Hash-chain зберігає байти такого твердження, але не робить його істинним.

**Прийняття:** protected trap source і injected map error ніколи не породжують `EnforcedDrop`; successful apply має correlation із syscall result та за потреби packet witness.

## 4. Архітектура, яка полегшить зовнішнє рев’ю

Пропонований напрям — поступова декомпозиція з контрактами, без масштабного переписування:

```text
Detector / Operator / authenticated Peer
                |
      typed Command + actor + event_id + scope
                |
      Policy -> desired intent -> reconciliation
                                |              |
                          Kernel adapter    GoBGP adapter
                                |              |
                          applied/failed    observed RIB
                                \              /
                          typed outcome + audit
                                  |
                         query API -> dashboard
```

1. **Policy/domain crate:** `BlockTarget`, `Actor`, `BlockOwner`, `Lease`, `Revision`, `EnforcementOutcome`; pure rules і injected monotonic clock. Політика protected addresses має один owner. Зміни адрес/маршрутів хоста після старту зараз слід окремо перевірити: snapshot захисту будується під час запуску; production потребує refresh/netlink subscription або чітко обмеженого deployment contract.
2. **Linux adapter:** map operations/lookup, attach lifecycle, counters і packet parsing. Явна межа `unsafe`, reason для кожного fail-open/fail-closed. Kernel verifier safety не доводить policy correctness.
3. **State reconciliation:** desired/applied/observed розділені; жодного success до side-effect result. Durable state має version/migration/recovery policy. Не потрібно зберігати весь traffic event stream як database стану правил.
4. **Mesh:** protocol version, sender authority, command ID, per-origin lease/revision, quotas, delivery semantics. Pinned peer зараз отримує широку block authority; pinning не означає обмеження blast radius compromised trusted node. Формально визначити допустимі prefixes, TTL, rate і види commands для кожного peer.
5. **Audit:** structured versioned events, identity/correlation/outcome, independent writer health. Окремі SLO для enforcement latency і audit durability. Черга sampled drops не повинна без видимого accounting витісняти operator decision events.
6. **Supervisor:** зберігати task handles, readiness critical listeners, fatal/degraded state і shutdown deadline. Не вважати процес healthy лише тому, що main loop жива; `tokio::spawn` error у critical service має явний operational effect.
7. **Operator:** прибрати authoritative state з HTML/web layer; не тримати global nodes write lock на час зовнішнього socket I/O. Статичні UI assets відокремити від Rust string, мати локальні assets/CSP для операційного dashboard; зараз `sokol-operator.rs:592–593` завантажує Tailwind CDN і unversioned Chart.js CDN.

`ai` зараз не підключений до enforcement і має 0 тестів; це чесно описаний експериментальний компонент. Визначити його як experimental crate з власними admission criteria, або прибрати з supported product surface. Не робити його production detector без dataset provenance, labels, calibration, false-positive/negative tradeoff та відтворюваних evaluation runs. Простий threshold derivative `SokolEngine` слід називати threshold detector; math type names самі собою не додають доказовості.

## 5. План реалізації з критеріями завершення

Оцінки — орієнтовні engineering days, не календарні обіцянки; залежать від доступу до Linux/BGP стенда. Рекомендовано невеликі PR за інваріантами, а не один великий refactor.

| Етап / порядок | Робота | Орієнтовний обсяг | Gate завершення |
|---|---|---:|---|
| A1 | F01/F02: transactional map bookkeeping, typed bulk results | 2–4 дні | fault-injection + Linux full-map/retry + packet witness |
| A2 | F06: block precedence, parser error policy, corpus | 2–4 дні | IPv4/IPv6 malformed/fragment corpus + verifier на supported kernels |
| A3 | F07/F12: audit result truth, sync deadlines, writer lock | 3–5 днів | disk faults, dual writer, periodic fsync, truthful refusal events |
| B1 | F03/F04: Flowspec lifecycle, actual-state reconciliation | 4–7 днів | restart/crash matrix, foreign rule ownership, bounded cleanup |
| B2 | F05/F09: delivery semantics, idempotent IDs, repair | 4–7 днів | queue loss, reorder, duplicate, partition/heal, adapter outage |
| C1 | F08/F11: daemon query/flush, telemetry identity/framing, quotas | 3–5 днів | restart UI, stale status, split frames, local overload |
| C2 | F10: measurement correctness і raw artifacts | 2–3 дні | deliberate broken enforcement makes benchmark fail |
| D | reproducible CI, supported-platform matrix, release evidence | 3–5 днів | fresh clone build з pinned inputs; reviewer replay package |

Залежності: A1 перед credible metrics/benchmark і Flowspec integration; outcome schema A3 перед уніфікацією ACK; B1/B2 можуть розроблятися окремими bounded змінами після узгодження domain types. Real-NIC throughput campaign — після correctness gates, окремо від цих оцінок.

Не відкладати виправлення F01/F02 заради нового database/framework. Мінімальне безпечне виправлення порядку операцій можна зробити раніше за повну desired/applied модель.

## 6. Тестова стратегія для строгого reviewer

### Інваріанти як приймальні контракти

| Інваріант | Незалежний oracle |
|---|---|
| Applied block відповідає реальному kernel entry | kernel lookup + packet probe, не той самий tracker |
| Unban/expiry success означає зняття відповідного правила | absence lookup + дозволений packet; врахувати covering prefix |
| Protected targets не блокуються жодним actor | IPv4/v6/CIDR property tests для кожного ingress |
| State збігається після reconnect/restart | порівняння по origin/revision і kernel/RIB readback |
| Будь-який ресурс має quota, timeout або lifecycle bound | saturation test + RSS/FD/task metrics |
| Audit outcome відповідає side effect | fault injection до/після apply, correlation ID |
| Flush durability ack означає успішний sync | syscall fault + typed error assertion |
| Benchmark failure не стає числовим success | deliberate fault і nonzero exit |

Property/model-based tests потрібні для послідовностей `block/repeat/sync/unblock/expire/restart/fail`, а не лише для кожної функції окремо. Важливі перекриття host/prefix, mapped IPv6, permanent+dynamic owners, same event duplicate, retained strike history, TTL renewal та clock skew. Обрати й задокументувати семантику unblock за наявності кількох owners.

Fuzz targets: packet parser corpus; mesh envelope framing/deserialize; custom canonical JSON parser (escaped equivalent keys, nesting, duplicate handling); IPC parser; audit header/rotation/recovery. Для canonical parser це напрям перевірки, **не твердження про доведений signature bypass**. Криптопідпис покриває payload bytes, а typed serde має свої перевірки.

Failure matrix: map-full, EIO/ENOSPC, partial write, stalled child, late child success, full channel, dead receiver, reordered/replayed envelope, reconnect під час snapshot, duplicate connections одного node, SIGKILL кожного процесу, disk/network outage і clock adjustments. Для кожного: очікуваний state, observable symptom, recovery, bounded resource cost.

Native NIC tests: зафіксовані kernel/driver/firmware/MTU/offloads/queues/CPU affinity/NUMA; packet sizes і packet mix; drop/pass окремо; empty/80%/full trie; дозволений traffic під flood; p50/p95/p99 control latency; CPU/RSS/packet loss/доступність керування; повтори й raw samples. Число Mpps без цього не є переносимою характеристикою продукту.

## 7. CI, відтворюваність і поставка

Поточний CI уже будує eBPF перед orchestrator, запускає tests/clippy і Linux smoke/demo. Прогалини в checked-in `.github/workflows/ci.yml`:

- Floating `nightly` у двох toolchain files та CI; action tags `@v4/@v2`; downloaded bpf-linker/GoBGP архіви без digest verification. Lockfiles корисні, але не фіксують compiler, runner і tools.
- Є лише один runner flavor; README заявляє Linux 5.15+, але workflow не доводить minimum-kernel compatibility. Перевірити 5.15 і selected current supported kernel; архітектури лише ті, що реально заявляються supported.
- Build steps мають `--locked`; test/clippy steps — ні. Уніфікувати frozen dependency resolution у release verification.
- Smoke cleanup видаляє `$WORK` навіть після failure. Додати artifact upload `if: always()` з bounded logs, configs без secrets, verifier output, test summary, source/artifact digest.
- Немає checked-in dependency advisory/license policy, fuzz job, release provenance або reviewer template. Наявність зовнішніх налаштувань GitHub не досліджувалась, тому branch protection/CODEOWNERS enforcement не оцінюється як «відсутній» без readback.

Release package: точний source SHA, dirty flag, rustc/LLVM/linker/GoBGP versions, locks/digests, eBPF object hash, executable hash, kernel test matrix, signed/attested build provenance за прийнятою моделлю довіри, upgrade/rollback procedure та відомі limitations. Digest доводить тотожність байтів; correctness доводиться окремими tests і review.

## 8. Культура розробки та підхід до claims

### Замість загального «готово» — доказ для кожного твердження

`ROADMAP.md` містить checked items, які поєднують кілька outcomes: наприклад 0.1 позначений виконаним, тоді як header лишає rewriting history рішенням власниці; 1.1 описує first-fragment режим з LRU у підпункті, але поточний parser не має такого LRU. Це розрив структури статусів, а не підстава переписувати історію чи впроваджувати LRU без потреби.

Для кожної capability завести компактний record:

```text
Claim / supported scope
Invariant and explicit non-goals
Implementation owner and commit
Reproduction command and expected result
Observed evidence artifact / environment
Known failure modes and unresolved findings
Independent reviewer verdict on exact commit
```

Зелений CI — baseline evidence. Для критичної зміни reviewer має окремо спробувати порушити інваріант, а не лише повторити авторський happy path. Не потрібна бюрократія на кожен label/CSS change; вимога масштабується до blast radius.

### Практики, які реально покращать зовнішнє рев’ю

1. **Малі PR за одним інваріантом.** Description: concrete trigger, before/after, failure behavior, tests, upgrade impact. Окремо correctness fix і необов’язковий refactor.
2. **Незалежний counterexample review для ядра/mesh/routing/audit.** Автор тестів і reviewer шукають різні failure modes; acceptance прив’язана до SHA. Новий push анулює висновки лише в зачепленій частині, але вимагає перевірки нового head.
3. **ADR на спірні semantics.** Permanent ban після restart? Хто може зняти чужий block? Що означає «доставлено»? Що робити без audit? Який expected fail-open? Відповідь має існувати до реалізації.
4. **Incident learning.** Кожний escaped defect залишає minimal reproduction, пояснення порушеного припущення і test на наступну операцію після fault. Без пошуку винного; не зводити root cause до «не вистачало тестів».
5. **Одна актуальна таблиця capabilities.** README пояснює використання; roadmap описує майбутню роботу; evidence records несуть статус. Не дублювати суперечливі «все виправлено» у кількох місцях.
6. **Прозорий AI-assisted development.** Генерований код проходить ті самі gates; model narrative не рахується test evidence. Людина/відповідальний maintainer володіє semantics і прийняттям risk.
7. **Операційне тренування.** Operator має практично виконати key revoke, mistaken block recovery, disk-full handling, dead GoBGP recovery, rollback, audit verification. Runbook без rehearsal — ще не готова процедура.

До зовнішнього reviewer передавати: цей report із disposition findings, невеликий architecture/authority map, supported-scope statement, pinned build, мінімальні repros, artifacts Linux validation, known limitations. Сам reviewer має мати змогу отримати той самий результат із fresh checkout, без довіри до повідомлення «перевірено запуском».

## 9. Що не слід стверджувати на основі цього рев’ю

- Не доведено production readiness, відсутність інших vulnerabilities чи performance на реальному NIC.
- Не доведено cryptographic break, remote code execution або доставку malformed IPv6 payload застосунку.
- Не оцінено live CI, організаційні permissions, deployment umask, стан routers або зовнішню мережеву політику.
- Linux-specific workspace build failure на macOS не рахується product defect; потрібне виділення portable domain tests для зручності перевірки.
- Розробку функцій не завершено: цей deliverable — review, evidence harness і implementation plan.

**Критерій переходу від pilot:** закриті P1 з Linux regression evidence; доведена convergence після відмов; правдиві applied/durable outcomes; defined support/authority scope; відтворюваний build і незалежне прийняття конкретного candidate commit. Тільки після цього performance qualification визначає допустимі deployment limits.
