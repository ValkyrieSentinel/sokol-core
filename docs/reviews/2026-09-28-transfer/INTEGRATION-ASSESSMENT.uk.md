---
chord:
  primary: "oct:5"
  secondary: ["oct:3"]
energy: 0.7
mode: "REVIEW"
tension: "production-before-adaptation"
confidence: "medium"
receipt: "test"
---

# Що перенести з Biophoton, Hardware Filter та Omega у Sokol-Core

**Дата:** 2026-09-28. **Статус:** рекомендація; код інтеграції не внесений.
Основний критерій — production grade; другий — вимірювана здатність системи
відновлюватися й адаптуватися в межах наданих повноважень.

**Висновок:** найбільшу практичну цінність має культура перевірок Omega: контракти
розкладки даних, детерміновані переходи, відтворювані причини та тести життєздатності.
Із Biophoton варто взяти локальне відчуття навантаження й обмежену ціну сигналізації.
Із Hardware Filter — лише просту модель ознак та розділення швидкої реакції й дорогого
аналізу. Пряме підключення будь-якого з трьох проєктів зараз не рекомендую.

## 1. База та межі дослідження

| Репозиторій | Перевірений commit | Обсяг читання |
|---|---|---|
| Sokol-Core | `b8e0e232853054d1155191f2ca895097bf0e4014` | Поточні ADR, support/lab, common, ATP, defense, state store, метрики й відповідні місця enforcement |
| Sokol-Biophoton | `87fecc63ccfd717192de3e67e352416e44cd2ee4` | Увесь Rust-код і manifest |
| Sokol-Hardware-Filter | `d1fea045bda0df5b857cb65ed46c0341cc0faf80` | Увесь Rust-код і manifest |
| Omega | `f557cd578e45de79878d3ca5d12b025f7d92a75b` | Вибрані Rust-модулі ресурсів, повідомлень, receipts і sync; TS recovery; тести; поточний контракт proof artifacts |

Це оцінка переносимості, не повний аудит Omega чи повторна кваліфікація Sokol.
Історичні виключені workspace-напрями не використовувалися як джерело повноважень.
Точні команди, версії інструментів і стани checkout: [manifest](evidence/manifest.json).
Посилання на код нижче прив'язані до commit, а не рухомої гілки.

Sokol уже має значну частину потрібного фундаменту: bounded ресурси мешу й пріоритети
черг ([ADR-0013][resources]), облік наслідків блокувань ([ADR-0014][outcomes]),
неблокуючий state writer, контрольоване відновлення, версію стану, захист локальних/WG
адрес та CI для arm64. Тому «додати ATP», «додати пам'ять» чи «додати backpressure»
без порівняння з цим кодом означало б дублювати механізми.

Нові [лабораторні результати][lab] охоплюють до 30 вузлів, заповнення таблиці й
годинний soak на 20 вузлах. Це дані репозиторію, **не повторені в цьому дослідженні**.
Вони не доводять native-XDP продуктивність на фізичній NIC, довгострокове плато RSS
або поведінку незалежних годинників. Ці задачі мають вищий пріоритет за новий біопротокол.

## 2. Матриця перенесення

| Ідея | Джерело | Рішення | Куди в Core | Умова прийняття |
|---|---|---|---|---|
| Виконуваний ABI-контракт | Omega `ffi_layout` | **Зараз** | `common` + kernel smoke | size/align/offset, реальний producer→consumer, обидві архітектури |
| Тести життєздатності й причинного впливу | Omega `habitability`, `hebbian_is_load_bearing` | **Зараз** | Наявні model tests і `bench` | Система відновлює корисну роботу; вимкнення механізму ламає відповідний gate |
| Receipt із контекстом відтворення | Omega `mitosis_log`, proof identity | **Наступний крок** | Існуючі audit/outcomes/support bundle | Офлайн-відтворення рішення або явне `insufficient evidence` |
| Локальний профіль навантаження | Biophoton metabolism | **Shadow після baseline** | `metrics` → pure observer | Обмежена ціна, згасання, відсутність enforcement-повноважень |
| Обмежений fast/slow шлях | Hardware `DualFoveaPipeline` | **Лише за профілем навантаження** | Існуючі XDP events → bounded worker | Менша виміряна ціна без втрати захисту й керування |
| Типізована бітова маска ознак | Hardware state vector | **За конкретної потреби** | Малий модуль `common` | Явний NoMatch, пріоритети policy, без unsafe |
| Q-format для оцінок | Omega integer arithmetic | **За потреби детермінізму** | Shadow policy/replay | Одиниці, rounding, saturation, scale/version зафіксовані |
| Wave/quorum, власна unsafe-черга, Omega runtime | Усі три | **Не переносити** | — | Немає обґрунтованої production-потреби; є суттєві ризики |

«Зараз» означає рекомендований наступний пакет, а не вже реалізовану зміну.

## 3. Biophoton: корисна нервова система, незрілий транспорт

[Реалізація][bio] — компактний експеримент із метаболізмом, emitter/receptor і
9-байтовим pulse. Це ще не протокол довіреного поширення сигналів небезпеки.

### Що зберегти

**Відчуття власних меж.** Вузол має знати, скільки коштує його захист, і залишати
ресурс на expiry, recovery та операторське керування. Це практичний зміст метаболізму.
Окремі бюджети потрібні для конкретних робіт; один абстрактний ATP не замінює
ліміти CPU, bytes, черг і диска. У Core вже є `AtpBudgetController` і token buckets.

**Дешевий сигнал замість важкої реакції.** Локальний сплеск можна звести до малого
повідомлення про стан. Якщо колись потрібне поширення, використати наявний
автентифікований mesh, версіоновану схему, freshness і низький пріоритет.
Підпис засвідчує відправника, але не правдивість його стресу. Чужий сигнал не має
самостійно вмикати strict mode, створювати block claim чи змінювати protected set.

### Чому не імпортувати crate як є

Відтворено на точному вихідному `lib.rs`:

| Спостереження | Наслідок для інтеграції |
|---|---|
| Повтор того самого pulse двічі дає приблизно 4× енергії першого, emitter count лишається 1 | Повторне доставлення стає додатковим «свідченням»; немає replay-контракту |
| Пакет типу 2 з довільним emitter ID заносить його в blacklist | Відправник може назвати чужий ID; у receptor немає автентифікації |
| `distance_metric = 0` породжує non-finite energy | Вхідні параметри не мають потрібного числового контракту |
| Після 1000 тихих tick поле згасає, але stress не спадає | Відсутня повна петля повернення до базового стану |
| Зміна `content_hash` не змінює reception | Поле не зв'язує реакцію з перевіреним контентом |
| `sin(π)` у локальному наближенні має помилку понад 0.5 | Фазова модель потребує окремої числової валідації |

Додатково: raw packed bytes мають native endian; немає version, TTL та підпису;
16-бітний hash непридатний як сильна ідентичність evidence. Підрахунок довільних
emitter IDs не є quorum незалежних довірених учасників. `no_std` не означає ні
відсутність ефектів, ні готовність до BPF verifier; тут використано float-арифметику.

**Мінімальний корисний спадкоємець:** pure `StressObserver` із часовим кроком,
окремими осями навантаження, recovery/decay, hysteresis і явним `unknown` при втраті
даних. Вихід — метрика/пояснення, не команда. Перші входи вже існують:
`sokol_tick_seconds`, `sokol_state_pending_seconds`,
`sokol_blocks_pending_oldest_seconds`, втрати audit і bulk-черги.
Пороги належить калібрувати на baseline, а не виводити з біологічної назви.

## 4. Hardware Filter: прості примітиви під сильними назвами

[Код][hardware] реалізує mask, bitset, вибір за молодшим бітом, порівняння з порогом
і лічильники. Тут немає завантажуваного XDP-program чи результату verifier/pps-тесту.
«Quantum», «spectral» та «hardware» не додають цим операціям нової семантики.

Корисний напрям — компактні типізовані ознаки та обмежений шлях дорогого аналізу.
Однак XDP уже має cheap decisions і [rate-limited ring buffer][xdp]. Спочатку треба
показати конкретний bottleneck і порівняти кандидат із цим baseline.

**Блокери прямого reuse:**

- `EMPTY.collapse()` обирає `decision_table[0]`, як і встановлений bit 0.
  Відсутність ознак може стати дією DROP залежно від таблиці. Це підтверджено тестом.
- За кількох ознак перемагає молодший біт; semantic priority не визначено.
  `fast_features > threshold` порівнює числове кодування flags, а не обґрунтовану
  тяжкість. Потрібні явні правила NoMatch та конфлікту ознак.
- `FastCffBuffer` оголошує `Sync`, але дозволяє конкурентні записи в той самий
  `UnsafeCell`. Для допустимого `N=1` два потоки отримують різні значення atomic head,
  проте обидва пишуть slot 0 без взаємного виключення. `fetch_add`, навіть із сильнішим
  Ordering, не серіалізує наступні неатомарні записи. Це статично встановлений шлях
  data race; UB навмисно не запускали. Також немає reader/tail/overrun-контракту.
- Власний безумовний для dependency `panic_handler` конфліктує зі `std` споживачем:
  окрема компіляція повертає `E0152: duplicate ... panic_impl`. Це підтверджено.

Не переносити unsafe buffer. У kernel зберегти BPF ringbuf, у userspace — наявні
bounded queues. Для можливого нового feature selector вистачить безпечного Rust:
`NoMatch | Observe | Candidate`, явної таблиці пріоритетів і окремої policy-перевірки.
Protected-target policy має лишитися обов'язковою на шляху застосування рішення;
сам feature mask її не замінює.

## 5. Omega: переносити перевірювані закони та метод роботи

### 5.1. ABI як тест, а не коментар

[`ffi_layout.rs`][ffi] перевіряє розміри, вирівнювання та зміщення полів.
Для Sokol аналог потрібен на межі userspace↔BPF: `PacketStats`, `DropEvent`,
конфігурація карт та значення block-hit slots. Простий host layout test — лише
перша половина: smoke має прочитати подію, сформовану справжнім BPF producer.
Історія arm64 alignment у ADR-0014 показує, чому цього не можна замінити x86 тестом.
Розкладка ABI не є мережевою серіалізацією: wire потребує власного контракту bytes.

### 5.2. «Живий» означає здатний виконувати корисну роботу після збурення

[`habitability.rs`][habit] перевіряє виживання, баланс ресурсів і досяжність
розмноження; [`hebbian_is_load_bearing.rs`][hebb] порівнює два світи, що різняться
тільки одним механізмом. Це не доводить біологічну універсальність, але є сильним
інженерним методом: функція може виконуватися й нічого корисного не змінювати.

У Core вже є model/property та mutation tests. Наступне розширення — **системний
контракт recovery**, а не ще один фреймворк тестування:

1. Перевантажити bulk telemetry, лишивши потік чинних claims і operator commands.
   Перевірити progress, latency та відсутність несанкціонованих блоків.
2. Прибрати навантаження: черги та dirty age повертаються до погоджених меж,
   leases закінчуються, strict-state не залипає, protected traffic працює.
3. Пройти churn довше горизонту retention або прискорений еквівалент плюс реальний
   soak. RSS і розмір state мають досягати обґрунтованої межі, не лише пережити годину.
4. Зламати ключову залежність контрольованою мутацією: пропустити refill/expiry,
   ігнорувати desired→applied retry, забрати пріоритет claims. Відповідний gate має впасти.

Числові acceptance limits записати **до** прогону для конкретного deployment.
Невідоме або загублене вимірювання не зараховувати як успіх.

### 5.3. Пам'ять із контекстом, достатнім для повторного обчислення

[`MitosisReceipt`][receipt] зберігає вхідний стан, результат і параметри.
Корисний аналог для Sokol — не новий журнал, а розширення наявного outcome/audit
контракту: schema, claim IDs, policy/config digest, build identity, важливі входи,
рішення, apply outcome, lifecycle times, evidence availability і gaps.

Перший споживач — офлайн replay/report. Дешевий запис може містити посилання на
збережений контекст; якщо контекст втрачений, replay повертає `insufficient evidence`.
Не обіцяти відтворення рішення за одним free-text cause або кількістю dropped packets.
Вони не доводять ані шкідливість трафіку, ані користь блокування; ADR-0014 це вже визнає.
Визначити bounds, retention, redaction і ціну snapshot до збору пакетних payloads.

[Поточний контракт SP1 artifacts][proof] додає важливий урок: evidence стосується
**конкретної програми та параметрів**. Для Sokol корисні version/digest і rejection
невідповідного replay-контексту. SP1, GPU, lattice runtime чи доказ на кожен пакет
для цього не потрібні. Самі SP1 proofs у цій роботі не перевірялися.

### 5.4. Обмежений recovery і чесна арифметика

[`sync_recovery.ts`][recovery] відокремлює стан recovery від мережевого I/O, має
timeout і захист від повторного зависання на тому самому повідомленні. Переносити
метод pure transition + injected clock, а не правило «більший remote trace має владу».
Для Sokol збій peer sync не повинен зупиняти локальне expiry/enforcement.
Anti-flap потрібен із загальним бюджетом і cooldown: нові attacker-controlled IDs
не повинні безкінечно відновлювати recovery episode.

[`resolve_stake`][thermo] показує цілочисельний облік із явним розподілом ресурсу.
Це доречний приклад для invariants budget, але stake/slashing не відповідають
семантиці мережевого захисту. Також не весь код Omega однаково строгий:
`ThermodynamicDelta::accumulate` використовує wrapping, а в
[`ResilienceSnapshot::from_counts`][snapshot] коментар обіцяє clamp до 1, якого
формула не робить при `double_witness > total`. Тож запозичувати слід контракт із
власними boundary tests, а не припускати correctness через Q-format чи назву.

## 6. Пропонована архітектура інтеграції

```text
Kernel / detectors / local health
              │ bounded observations + provenance
              ▼
Existing metrics + audit/outcomes ──► bounded offline replay
              │                                │
              ▼                                ▼
Pure local StressObserver               shadow proposals
              │                                │
        metrics / explanation           policy review + explicit adoption
                                               │
                                               ▼
                            Existing authority / protected set / lease gates
                                               │
                                               ▼
                                  Existing reconciliation → kernel
```

Shadow observer не отримує map handles, signing key чи доступу до operator socket.
Його відмова не затримує maintenance. Пропозиція з policy digest, діапазоном дії,
evidence і строком придатності стає дією лише через чинний процес прийняття policy.
Один аварійний перемикач вимикає адаптивний додаток без вимкнення базового захисту.

Біоаналогія тут точна: **рефлекс → відчуття наслідків → відновлення → навчання**.
Мембрана задає допустимі дії; метаболізм обмежує їхню ціну; пам'ять дозволяє перевірити
результат. «Живість» не вимагає геномів або самовільної зміни повноважень.

Колірні badges можна генерувати як представлення цих метаданих. Capability/effects,
вартість та стабільність — різні осі; «температура» не є доказом безпечності чи підставою
заморозити модуль. `scale/Q` — явна числова версія оцінки, а не механізм довіри.
Кольорові назви мережевих сервісів можуть бути UI-словником; перенумерація портів
чи прихований канал сигналізації не потрібні цьому плану.

## 7. Послідовність робіт та критерії зупинки

| Пакет | Горизонт* | Конкретна зміна | Gate |
|---|---|---|---|
| T1 | Найближчий цикл | ABI contract + missing producer/consumer checks | x86/arm64, помилка layout ловиться; kernel smoke лишається обов'язковим |
| T2 | Найближчі 1–2 цикли | Розширити існуючий lab recovery/churn сценаріями | Прогрес керування, повернення до baseline, retention plateau; deliberate mutants виявляються |
| T3 | Середньостроково, після визначення schema | Малий replay bundle на базі outcomes, версіоновані policy/build IDs | Одна подія відтворюється; missing/mismatched context чесно відхиляється |
| T4 | Після baseline, орієнтовно 1–3 місяці | Локальний observer, спочатку offline replay, далі opt-in shadow | Визначена ціна; bounded state; відновлення після burst; нуль нових enforcement-рішень |
| T5 | Після пілоту, орієнтовно 3–6+ місяців | Shadow-пропозиції для вузького параметра, наприклад telemetry sampling | Порівняння з baseline на окремому evaluation corpus; rollback; явно прийняті межі |

\* Це порядок залежностей та оцінка горизонту, не календарне зобов'язання.
Паралельно основний production-потік: цільова NIC/native XDP, тривалий soak,
відновлення після disk/clock/network failures і контрольований deployment pilot.

**Першими зробити T1 і T2.** T3 готує ґрунт для обґрунтованої адаптації. T4/T5
не блокують production qualification і не повинні її відтісняти.
Feature-mask rewrite відкласти до виміряного bottleneck; окремого нового crate не
виділяти до появи другого реального споживача та стабільного контракту.

Зупинити або відкотити експеримент, якщо він збільшує tick latency понад заданий
бюджет, губить provenance, відновлюється лише рестартом, потребує необмеженої пам'яті
або отримує обхід policy. Якщо shadow не дає виміряної користі проти простого baseline,
залишити метрики й прибрати складнішу модель.

Перед копіюванням коду окремо узгодити reuse: Omega декларує AGPL-3.0-or-later,
а [dependency policy Core][deny] дозволяє лише перелічені permissive licenses.
У двох малих прототипів немає декларації `package.license` або LICENSE у переглянутому
дереві. Це невирішене питання для прямого reuse; спільний власник репозиторіїв сам
по собі не змінює чинну policy. Цей документ переносить ідеї та вимоги, не вихідний код.

## 8. Що перевірено виконанням

- **Biophoton:** 6/6 діагностичних probes підтвердили описані обмеження.
- **Hardware Filter:** 2/2 probes підтвердили семантику collapse; std-consumer
  окремо не скомпілювався з очікуваним `E0152`.
- **Omega:** 14/14 тестів: ABI — 7, golden vector — 1, habitability — 4,
  причинний вплив Hebbian weights — 2. Це вибірка, не результат усього test suite.
- Data race hardware buffer встановлено статичним розбором; Miri/TSan не запускали.
- XDP/NIC benchmark, Linux smoke, SP1 verification/proving та повний Omega audit
  в межах цієї оцінки не виконувалися.

[Відтворення probes](evidence/reproduce.py), [результати](evidence/prototype-probes.json),
[журнал Omega tests](evidence/omega-tests.txt). Probes компілюють точний `lib.rs` із
доданими тестами через rustc; вони не перевіряють Cargo packaging чи всю dependency graph.
Тимчасові збірки не змінюють оригінальні джерела. Зелений diagnostic probe тут означає
«обмеження відтворене», а не «прототип готовий до production».

[bio]: https://github.com/ValkyrieSentinel/sokol-biophoton/blob/87fecc63ccfd717192de3e67e352416e44cd2ee4/src/lib.rs
[hardware]: https://github.com/ValkyrieSentinel/sokol-hardware-filter/blob/d1fea045bda0df5b857cb65ed46c0341cc0faf80/src/lib.rs#L44-L80
[ffi]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/omega_v2/tests/ffi_layout.rs
[habit]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/omega_v2/tests/habitability.rs
[hebb]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/omega_v2/tests/hebbian_is_load_bearing.rs
[receipt]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/omega_v2/src/mitosis_log.rs#L20-L44
[proof]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/omega_zk_host/proofs/README.md
[recovery]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/src/network/sync_recovery.ts
[thermo]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/omega_v2/src/thermodynamics.rs
[snapshot]: https://github.com/s0fractal/genesis/blob/f557cd578e45de79878d3ca5d12b025f7d92a75b/omega_v2/src/resilience_snapshot.rs#L76-L100
[resources]: https://github.com/ValkyrieSentinel/sokol-core/blob/b8e0e232853054d1155191f2ca895097bf0e4014/docs/adr/0013-resource-limits.md
[outcomes]: https://github.com/ValkyrieSentinel/sokol-core/blob/b8e0e232853054d1155191f2ca895097bf0e4014/docs/adr/0014-block-outcomes.md
[lab]: https://github.com/ValkyrieSentinel/sokol-core/blob/b8e0e232853054d1155191f2ca895097bf0e4014/docs/measurements/2026-09-27-lab/README.md
[xdp]: https://github.com/ValkyrieSentinel/sokol-core/blob/b8e0e232853054d1155191f2ca895097bf0e4014/ebpf/src/main.rs#L139
[deny]: https://github.com/ValkyrieSentinel/sokol-core/blob/b8e0e232853054d1155191f2ca895097bf0e4014/deny.toml
