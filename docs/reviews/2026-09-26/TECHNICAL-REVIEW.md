# Sokol-Core: повторне технічне рев’ю — авторство, збіжність, ресурсні межі

Дата: **2026-09-26**. Перевірений актуальний `origin/main`: **`5fbacdc7c7af94be0ac1e58262af381f8e9fdb0c`**, отриманий `git fetch origin main` під час рев’ю.

Локальна гілка `fix/adapter-delivery-ack` залишена на `47f224412f6168a347df163d53f8160658941e6d`. Її runtime-код ідентичний перевіреному main; різниця — новий `ARCHITECTURE.md` і виправлений `bench/local.sh`. Tests виконані на окремому експорті exact main через `git archive`, без checkout або змін продуктових файлів. Попередній звіт і evidence збережені. Початкові untracked `docs/` — результати попереднього рев’ю.

## 1. Головний висновок

**Зміни суттєво покращили correctness, але нова модель довіри ще не забезпечує заявлений захист від одного скомпрометованого peer.** Один справжній pinned key може через `BlockSync` представити кілька вигаданих issuers, обійти quorum і персональні квоти. Це найвищий пріоритет цього рев’ю.

Другий системний ризик — розрив між обмеженнями окремих структур і обмеженнями всього циклу обробки: кількість claims, строк зберігання tombstones, розмір закодованого snapshot, число операцій retry та вартість збереження стану не утворюють спільного ресурсного контракту.

Рекомендую залишити **Pilot**, тимчасово не покладатися на quorum як containment для compromised peer і не розширювати mesh до виправлення R26-01/02/03. Новий функціонал варто нарощувати після перевірки цих меж. Це інженерна рекомендація, не рішення про вимкнення наявного deployment.

Обрані вектори:

1. Чи автентифікація транспорту справді доводить авторство кожного рішення?
2. Чи стан збігається після втрат і чи кожний snapshot можна передати?
3. Чи ACK і restart мають визначену семантику durability та ідемпотентності?
4. Чи обмежена робота й пам’ять під тривалим, а не лише коротким навантаженням?
5. Чи формальна модель, документація й tests перевіряють саме production-шляхи?

## 2. Що вдалося покращити

Попередні F01/F02 вже не описують поточний алгоритм: є `Blocklist` trait, окремі claims/applied/pending, retry map faults і тести наступної операції після failure. Це правильна архітектурна відповідь.

Інші сильні зміни:

- Flowspec читає observed RIB, використовує ownership community, працює окремим worker; subprocess має `kill_on_drop(true)`.
- Audit має exclusive lock, відстежує здоров’я writer, помилки, втрати й sync deadline; flush повертає підтвердження.
- Operator отримує стан із daemon; є server-side flush, stale handling, telemetry credentials і connection limits.
- Detector adapters мають bounded outbox і application ACK. Документ прямо визнає volatile queue та можливість зайвого strike після повтору.
- Anti-entropy через digest дає шлях відновлення після пропущеної розсилки.
- Новий benchmark перевіряє postconditions, зберігає raw artifacts, додає packet witnesses і контрольний traffic.
- `ARCHITECTURE.md` пов’язує рішення з implementation/tests і називає обмеження. Це корисна основа для зовнішнього reviewer.

**Це не blanket ACCEPT усіх виправлень:** поточні unit tests і читання коду не замінюють Linux, disk-fault і BGP-restart verification.

## 3. Метод і виконані перевірки

Середовище: macOS arm64; Linux kernel/XDP і справжні BGP sessions цього разу не запускалися. Не змінювалися мережа хоста, service configuration, branches або production code. Remote main перевірений; GitHub CI conclusions/branch protection не перевірялися.

| Перевірка | Результат |
|---|---|
| Workspace formatting на exact main | PASS |
| eBPF formatting | PASS |
| `cargo test -p common -p sokol_ai --locked` | common: 15 PASS; AI: 0 tests |
| Ізольований block-table/P2P harness | 55 PASS: 47 наявних tests + 8 review probes |
| З probes | 7 поведінкових контрприкладів і 1 контроль того, що ClaimId — звичайний hash |
| Full Linux workspace, eBPF verifier, packet corpus, real GoBGP | Не виконано |
| Exhaustive fuzzing, supply-chain advisory audit | Не виконано |

Артефакти: [скрипт відтворення](evidence/reproduce.py), [результати](evidence/results.txt), [checks](evidence/checks.json), [source hashes](evidence/sources.json), [harness lock](evidence/Cargo.lock).

```sh
python3 docs/reviews/2026-09-26/evidence/reproduce.py
```

Скрипт читає pinned Git commit, створює тимчасовий snapshot і Cargo harness. `block_table.rs` залишається вихідним, крім перенаправлення Aya imports на type stubs; операції справжнього kernel adapter навмисно `unreachable!`, а production domain працює через `FakeLists`/test implementations існуючого `Blocklist` trait. `p2p.rs` — оригінальний; protocol declarations та `claimed_sender` витягнуті з оригінального `mesh_sync.rs`. Нові tests додані лише в тимчасові копії. Це не окрема реалізація алгоритму.

**PASS review probe означає відтворення небажаної поведінки.** Це не regressions, що засвідчують її виправлення. Transport tests і новий quorum probe використовують loopback TCP. Quorum probe проходить справжні `P2PNetwork::serve`, handshake, signature verification і sender checks, отримує command із production reader channel та передає вкладені claims у production `adopt` із test map. Повний daemon/XDP не запускався; kernel packet drop не вимірювався.

Позначки: **R** — виконаний контрприклад, **S** — простежений статичний шлях. P1 — до розширення deployment, P2 — наступний етап. Це пріоритети виправлення, не CVSS. Звіт не є вичерпною сертифікацією безпеки.

## 4. Нові знахідки

### R26-01 — P1 / R+S: BlockSync дозволяє одному ключу вигадати quorum

**Місця:** `mesh_sync.rs:38–45,76–88`; `p2p.rs:940–959`; `main.rs:1502–1532`; `block_table.rs:346–373,499–555`.

Для прямого `Claim` transport перевіряє `claim.issuer == authenticated_peer`. Для `BlockSync` він перевіряє лише зовнішній `issuer`, а вкладені `claims` можуть належати будь-кому. Кожний `Claim` містить issuer, поля рішення та BLAKE3 ID, але не issuer signature. `adopt` не вимагає доказу походження й не перевіряє, що issuer узагалі є у trust store.

Виконаний `review_one_signed_snapshot_forges_quorum`:

1. У trust store є лише node 2 з одним справжнім ключем.
2. Цей ключ підписує `BlockSync { issuer: 2, claims: [issuer 3, issuer 4] }` для `198.51.96.0/20`.
3. Production TCP listener приймає handshake node 2, перевіряє підпис і sender identity та доставляє підроблений snapshot у command channel. `claimed_sender()` повертає 2.
4. Таблиця node 1 з quorum=2 приймає обидва claims і застосовує target у test map. Ключів 3 і 4 не існує у trust store цього сценарію.

**Наслідки:** compromised pinned peer може обійти multi-peer quorum, обмеження за issuer та attribution. Protected-target policy лишається окремим захистом і цим probe не обходиться. Не потрібні підробка Dilithium, доступ до чужого secret key або unauthenticated connection.

**Виправлення:** найменший containment — snapshots передають лише власні claims, а receiver перевіряє кожний вкладений issuer. Якщо потрібен transit forwarding, кожний claim має нести перевірюваний origin-signed immutable object, domain/version, issuer/key identity та визначену policy для revoked origins. Quorum рахує лише перевірені origins. Повноваження relay і origin повинні бути різними поняттями.

**Gate:** один pinned relay із сотнею вигаданих issuer IDs не підвищує quorum і не обходить quota. Покрити live claim, reconnect snapshot, digest repair, revoked origin і unknown origin. Такий тест потрібен на ingress boundary, а не лише на методі `adopt`.

### R26-02 — P1 / R+S: tombstones роблять snapshot більшим за дозволений кадр

**Місця:** `main.rs:755–790`; `mesh_sync.rs:69–70`; `p2p.rs:40,870–872`.

Claims розбиваються на chunks по 250, але **всі retracted IDs вкладаються в перший chunk**. Receiver відхиляє envelope понад 128 KiB. Producer не забезпечує відповідної byte limit.

`review_snapshot_tombstones_exceed_frame_limit`: 2 000 нормальних 64-hex IDs, нуль claims, реальні JSON signing і bincode framing → **137 453 bytes**, дозволено **131 072**. Якщо peer потребує такого catch-up, frame rejection руйнує саме механізм відновлення. Повторний reconnect надсилає той самий непридатний snapshot.

Кількість claims також не є byte bound: reason у claim змінного розміру. Тому виправити тільки список tombstones недостатньо.

**Виправлення:** один packing algorithm для encoded-byte budget обох типів записів; ліміт single record; облік signature/framing overhead. Snapshot generation має бути streaming/bounded, із continuation і визначеною поведінкою при втраті chunk.

**Gate:** 0/1/max claims; 2 000+ tombstones; максимально дозволені reasons; суміш обох; кожний serialized frame ≤ limit; reconnect/repair завершується без loop. Перевіряти serialized bytes, не оцінку «250 має вистачити».

### R26-03 — P1 / R: нове звичайне відкликання отримує нескінченний retention

**Місця:** `block_table.rs:201–211,557–581,779–780`.

`Retraction::default()` задає `forget_ms=None`. У `retract()` новий entry зливає цей default із кінцевим deadline через match, де будь-яке `None` дає `None`. Таким чином «ще не ініціалізований» стан стає «ніколи не забувати».

`review_retractions_never_expire` створює retraction невідомого ID від node 2. Очікуваний за кодом `forget_ms` мав би бути `now + policy.max`; фактично він `None` і entry залишається після 100 таких інтервалів. Та сама ініціалізація діє при звичайному peer retract відомого claim. Local operator lift має інший шлях присвоєння, тому це не твердження про абсолютно всі tombstones.

**Наслідки:** накопичення записів до global cap, відмова приймати наступні нові retractions, постійна вартість обходу; разом із R26-02 — завеликий catch-up. Це накопичувальна відмова, яку короткий smoke легко пропускає.

**Виправлення:** розділити vacant entry і merge initialized entries; типізувати `Until/Forever`, не змішувати `Unset` із `Forever`. Garbage collection має відповідати threat model відкладених/replayed claims.

**Gate:** known/unknown claim, finite/infinite expiry, retraction-before-claim, repeated retract, restart, cap exhaustion; після допустимого horizon місце справді звільняється, але чинний tombstone не губиться раніше строку.

### R26-04 — P1 / S: ACK про прийняття не означає durable acceptance; shutdown не зберігає останній стан

**Місця:** `main.rs:793–807,824–832,1023–1040,2009–2025,2162–2179`; `delivery.rs:145–170`.

Outbox прибирає сигнал після `OK applied` або `OK pending`. Daemon змінює таблицю та відповідає до periodic `save_state`. State записується раз на tick; на shutdown є audit flush, але немає фінального save dirty block state.

**Статичний сценарій:** отримати ACK після останнього save → зупинити daemon до наступного tick → adapter уже прибрав подію → restart відновлює старий state. Для `pending` втрачається і обіцянка подальшого retry. Mesh іноді може повернути detector claim, але це не гарантована локальна durability, особливо для operator-only claims або single-node deployment.

Додатково `save_state` синхронно виконує serialize/write/fsync у головному async loop, а directory після rename не sync-иться. Розмір state збільшує затримку expiry/metrics/shutdown. `state_error` лише логують; NORMAL/DEGRADED залежить від audit health, а не від block-state persistence.

**Виправлення:** визначити окремо volatile/applied/durable ACK. Для обіцяного durable acceptance — journal/transaction до ACK; якщо свідомо допускається RPO, прямо назвати його й забезпечити redelivery. При shutdown спочатку зупинити admission, потім drain, save, sync і завершення. Worker для persistence з bounded backlog, state health і directory durability.

**Gate:** ACK→SIGTERM і ACK→SIGKILL у кожній фазі; ENOSPC на state path при здоровому audit; pending map operation через restart; жодного silent lost acknowledged intent поза визначеним контрактом. Цей crash test тут не запускався.

### R26-05 — P2 / R: memory cap не застосовується до local claims

**Місця:** `block_table.rs:188,451–493,514–516`; `ARCHITECTURE.md:413–414`.

`MAX_KNOWN_CLAIMS` перевіряється лише в `adopt`. `add_local` створює новий claim для кожного повторного detector event без цієї перевірки. Один applied target може мати дуже багато retained claims.

`review_local_claims_ignore_known_claim_limit` додає **262 145** локальних claims для одного IP: усі зберігаються, applied target — **1**, заявлений cap — **262 144**. Це не вимірювання реального OOM; це детерміноване перевищення конкретної межі. Доступ потрібен через local producer/детектор або інший authorized local path.

**Виправлення:** quota для local і remote admission окремо, count і byte budget; bounded history; семантично обґрунтоване coalescing повторів. Важливо не видалити IDs, які ще потрібні для retraction або dedup. Ліміт kernel map не є лімітом control-plane memory.

**Gate:** тривалий повтор одного target, різні targets, великий reason, pending і permanent claims; RSS, allocations, snapshot size, save latency мають задані межі. Reject/defer/coalesce обов’язково спостережувані.

### R26-06 — P2 / R: expired peer claims обходять бюджет kernel retry

**Місця:** `block_table.rs:715–726,736–744,782–783`.

`tick()` додає до `touched` усі claims із локальним минулим `until_ms`, а потім лише обмежує subset із `pending` через `take(256)`. Peer claim із `expires_ms=None` або далеким expiry залишається в shared state після локального cap. Якщо delete помилковий, наступний tick знову додає всі expired targets до `touched`, незалежно від pending limit.

`review_expired_targets_bypass_retry_budget` використовує 300 peer claims і fault-injected delete. На **другому** tick після локального expiry виконується **300 delete calls**, попри nominal budget 256.

**Виправлення:** єдина fair queue kernel reconciliation із count/time budget для всіх причин enqueue; expiry detection лише ставить target у queue. Окремо уникнути starvation від повторного `.take()` стабільного невдалого subset HashSet.

**Gate:** expiry, quota promotion, retract, operator flush і map failures одночасно; число syscalls та tick latency bounded; healthy targets прогресують поруч із постійно failing target.

### R26-07 — P2 / R: restart поновлює локальну lease того самого peer claim

**Місця:** `block_table.rs:520–521,814–853,870–954`; `ARCHITECTURE.md:340–346,435–436`.

Peer lease обмежується `now + max_ttl` при adoption. Durable state зберігає власні claims і lifts, але не факт першого прийняття peer claim і його локальне завершення. Повтор після restart отримує новий cap від нового `now`.

`review_replayed_capped_claim_gets_new_lease_after_restart`: той самий immutable claim із `expires_ms=None` перестає блокувати після local max; після persist/restore і повторного snapshot — знову `Enforced`. Нового рішення origin не було.

Це може бути допустимою «lease per receiver lifetime», але тоді `max_ttl` не є абсолютною межею впливу одного claim. Для containment це суттєва різниця.

**Виправлення/рішення:** явно обрати cumulative per-claim bound або renewable lease. Для першого — durable first-seen/end/rejection marker або origin-authenticated finite expiry з прийнятим clock policy. Для другого — документувати renewal authority і обмеження.

**Gate:** повтор того самого ID через daily restarts, retained peer snapshot, wall-clock jumps і expired local cap; критерій залежить від обраного контракту.

### R26-08 — P2 / S: storm latch переходить, але невдалий CONFIG update не повторюється

**Місця:** `mesh_sync.rs:233–279`; `main.rs:1584–1610`; `defense.rs:49–62`.

Latch генерує Engage/Disengage на transition, а handler один раз викликає `Defense::set`. Map error лише логують; desired state не ставиться на reconciliation retry. Якщо не вдався Disengage, strict flags можуть лишатися в XDP, хоча cluster latch уже clear. Для Engage — навпаки.

Це той самий клас розриву desired/applied, який правильно усунуто в BlockTable, але ще не перенесено на CONFIG.

**Виправлення:** latched desired mode → retry worker/periodic reconcile → applied flags і pending metric. Документувати, що є показником actual mode. State readback потрібен при підтримці зовнішніх writers.

**Gate:** inject set failure окремо на Engage і Disengage, не змінюючи cluster state вдруге; система сама доходить до desired mode, без false success. Тут — статична знахідка, не перевірка BPF map fault наживо.

## 5. Відомі tradeoffs, які потрібно свідомо прийняти

### Повтор ACK-доставки подовжує покарання

Документ уже визнає це (`ARCHITECTURE.md:571–572`), тому не подаю як новий прихований дефект. `review_duplicate_delivery_escalates_one_event` підтверджує: ті самі target/reason з новим processing timestamp дають **60 → 120 секунд** і різні IDs. При default 900 секунд кілька повторів швидко наближають TTL до max. ClaimId ідентифікує створене рішення; він не є detector event ID.

Розвиток: stable `(producer, event_id)` і durable dedup outcomes, повторний ACK без нового strike. Це має бути явним пріоритетом перед використанням ACK як гарантії доставки, що не змінює значення події.

### Benchmark став сильнішим, але оцінка onset ще умовна

Попередній F10 про silent polling timeout у свіжому main виправлений. Новий latency benchmark використовує `reply(M-1) + 2ms` як upper bound і серію unanswered probes. Інтервал `ping -i 0.002` є запитаним scheduling interval; код не вимірює фактичний send time M. Scheduling delay і selective loss не виключаються одним allowed-source control.

Отже називати це безумовною upper bound enforcement рано. Рекомендація: actual TX timestamps/packet sequence witness, measured jitter envelope і окрема unknown category; перевірка на навмисно затриманому generator. Сценарій на NIC тут не запускався, числових latency claims цей звіт не робить.

### Flowspec correctness тепер залежить від ownership і freshness

Observed RIB — суттєве покращення. Наступні tests: однаковий NLRI від двох local producers; tagged rule з іншим action; зміна wanted під час довгого round; shutdown під час round; readback після success. `parse_own_rules` перевіряє source/community, але не весь discard action, а worker використовує snapshot wanted на весь round. Це напрями перевірки, не доведене видалення чужих rules у цьому рев’ю.

## 6. Статус попередніх знахідок

| Попередня знахідка | Оцінка цього рев’ю |
|---|---|
| F01/F02 map bookkeeping | Перероблено; штатні fault tests у новому harness проходять. Linux gate ще окремо |
| F03 observed RIB | Основний defect виправлений у коді; real restart matrix тут не запускалася |
| F04 subprocess/tick | kill-on-drop й окремий worker є; persistence тепер окремий ризик tick latency |
| F05 пропущений broadcast | Є digest repair, але нові R26-01/02/03 обмежують безпечність і живучість цього repair |
| F06 IPv6 blocked-source parse error | Branch зберігає block precedence; live XDP test не повторено |
| F07 audit | Lock і writer health/deadline додані; common tests PASS; це не block-state durability |
| F08 dashboard state | Daemon query/flush і stale handling додані; тут static assessment |
| F09 adapter outage | Outbox+ACK є; volatile queue та duplicate strike документовані; R26-04 уточнює ACK boundary |
| F10 benchmark | На свіжому main є postconditions/raw evidence; onset bound потребує уточнення |
| F11 IPC/telemetry | Quotas, timeouts, uid checks додані; production permissions не інспектувалися |
| F12 false enforcement event | Typed outcome доданий; новий головний truth gap — desired/applied/durable transitions |

Ця таблиця не закриває issues автоматично й не замінює review конкретного fix candidate з Linux evidence.

## 7. План розвитку

### Етап A — відновити довірчу межу

**A1. Origin authenticity (R26-01).** Спершу bounded fix: own-only snapshots із перевіркою nested issuer. Для multi-hop — окреме рішення про signed claims, relay, revocation, replay horizon. Не додавати нову crypto scheme: проблема в межі підписаного об’єкта, а не в Dilithium.

**A2. Передаваний snapshot і retention (R26-02/03).** Byte-bounded encoder, chunking claims/tombstones, initialized tombstone semantics, cap/GC tests. Ці зміни приймати разом через reconnect/repair scenario, навіть якщо реалізація в окремих PR.

**Gate етапу:** один compromised pinned relay не створює чужих voters; великий коректний state передається після reconnect; stale tombstones не забивають store. Потрібні independent transport-boundary tests і Linux scenario, а не тільки pure quorum model.

### Етап B — транзакційна й ресурсна надійність

**B1. Acceptance contract (R26-04 + duplicate ACK).** Визначити `received/applied/durable` outcomes, event IDs, dedup і crash matrix. Persist owner records, lease facts і user-visible decisions у форматі з version/migration.

**B2. Єдиний ресурсний контракт (R26-05/06).** Max claims/bytes per source; fair reconciliation queue; monotonic time budget; bounded serialization; expiry index замість повного сканування там, де measurements покажуть bottleneck. Зберегти просту reference model для differential tests.

**B3. Configuration reconciliation (R26-08).** Block rules, storm flags і upstream rules повинні дотримуватись однакового принципу: desired → attempt → observed/applied → retry/error. Узгодити operational health цих трьох контурів.

**Gate етапу:** ACK→crash відтворюється за контрактом; disk stall не зупиняє expiry; локальний producer не обходить quota; failing syscall не позбавляє інші targets прогресу.

### Етап C — зовнішня перевірюваність

1. Виділити portable policy/state/protocol library зі штатними tests: reviewer не повинен створювати Aya stubs для domain proof.
2. Додати protocol version/capability negotiation або чіткий coordinated-upgrade procedure з rollback. Несумісність старого й нового wire protocol уже задокументована.
3. Зберігати minimal proof artifacts поруч із кодом: source SHA, command, expected output, negative control, actual output, environment. Приватні `lattice_check.py`/ADR/models згадуються в архітектурі, але в цьому repository вони не відтворювані для зовнішнього reviewer. Їх не завантажували й claims із них не приймали як перевірений доказ.
4. Pin toolchain/action revisions/download digests, CI artifact retention, supported-kernel matrix, packet fuzz corpus і privileged integration lane. Ці прогалини залишаються, частина прямо названа в архітектурі.
5. Throughput qualification виконувати після correctness: real NIC, packet mix, map utilization, legitimate traffic, CPU/NUMA/offloads і raw samples. Не переносити результати generic XDP на hardware line rate.

## 8. Практики рев’ю і культури

**Змістити фокус із «модуль має тест» на «інваріант переживає всі ingress і lifecycle paths».** Наявний direct-Claim sender test сильний, але не охоплює транзитний BlockSync; чиста quorum model правильно рахує різні IDs, але не доводить, що вони належать різним автентифікованим origins.

Рекомендована review matrix:

| Обіцянка | Перевірити на межах |
|---|---|
| Тільки issuer може створити claim | live, snapshot, repair, restore, unknown/revoked issuer |
| Доставка не змінює рішення | duplicate ACK, reconnect, producer restart, same event/new decision |
| Quorum означає незалежних учасників | один relay, підроблені IDs, rotation, той самий key під кількома IDs |
| Memory bounded | local/remote claims, reasons, tombstones, queues, serialization buffers |
| Applied/durable state правдивий | syscall fail, disk fail, partial write, crash і shutdown |
| Repair завершується | max frame, chunk loss, queue pressure, expiry/GC під час snapshot |

Для кожного security/correctness PR потрібні: названий invariant, конкретний counterexample до зміни, наступна операція після failure, новий exact SHA, незалежний adversarial review. Не перетворювати будь-яку docs/CSS зміну на такий самий процес.

Корисний принцип для моделей: усі model actors/IDs/claims мають відображення на перевірені runtime inputs. Доказ join laws над абстрактними множинами не доводить correctness admission, GC, quotas, auth, bounded encoding чи persistence. Замість широкого твердження «перестановки безпечні» вказувати prerequisites і tests, які перевіряють refinement implementation→model.

Документ архітектури вже визнає ряд tradeoffs — це сильна практика. Наступний крок: зв’язати кожне прийняте обмеження з deployment constraint, власником рішення і умовою перегляду. Зокрема ACK duplicates, peer lease renewal, ephemeral outbox, clock assumptions і single-host credentials мають впливати на те, де систему допустимо застосовувати.

Не роблю висновків про людей за кодом. Висновок про процес: виправлення локальних дефектів дало реальний прогрес; тепер найбільшу цінність дадуть composition tests та lifecycle proofs. Саме вони виявили дефекти, яких не видно з ізольовано правильних quorum, signature та snapshot механізмів.

## 9. Критерій наступного прийняття

Наступний candidate можна передавати на production-readiness review після закриття P1 із exact-head evidence, визначення acceptance/durability semantics, підтвердження resource bounds і живого Linux/BGP crash/repair прогону. Позитивні tests цього звіту не є дозволом на release або доказом відсутності інших дефектів.

Цей deliverable — нове рев’ю, відтворювані probes та план розвитку. Виправлення продуктового коду не виконувалися.
