# ADR-0008. Flowspec звіряється зі спостереженим RIB

**Статус:** реалізовано (PR #17). **Дата:** 2026-09-24.

**Уточнення 2026-10-05:** [ADR-0020](0020-flowspec-profile-and-backend.md) визначає
підтримуваний deployment-профіль, збереження CLI backend, правило зупинки розширень
і умови окремого gRPC-експерименту. Нижче збережено семантику та докази R1–R13;
ця історія не є планом наступних runtime-змін.

## Контекст

Вузол анонсує свої блоки вгору як правила BGP Flowspec «discard source» через GoBGP. Спершу він
пам'ятав, *що колись анонсував*, у пам'яті процесу. Після рестарту чи збою GoBGP ця пам'ять
розходилась із реальністю, і вузол міг видалити чуже правило (F03/F04).

## Рішення

- **Бажане** — активні блоки вузла. **Фактичне** — правила в RIB (`gobgp … -j`), а не пам'ять
  процесу. Робітник звіряє одне з одним.
- Після раунду зі змінами RIB читається повторно для обох сімейств: метрика рахує
  останні спостережені власні source-prefix правила, а не `+1/-1` за відповідями CLI.
  Без змін початкового читання досить. Помилка readback лишає попередню метрику;
  вона може бути застарілою. Її health відкликається до першого await наступного
  раунду й лишається 0 після помилки/скасування; успіх публікує кількість та початок
  читання разом. Метрики додають enabled, readback-ok і монотонний вік від початку
  читання (-1 до першого успіху); HTTP бере їх з worker, вік рахується при scrape.
  Споживач сам визначає допустимий вік. Запис `FLOWSPEC_ANNOUNCE`/`WITHDRAW` підтверджує CLI,
  не застосування маршрутизатором. Ownership і canonical discard рахуються окремо:
  `sokol_flowspec_discard_rules` — підмножина власних правил з рівно однією traffic-rate
  extended community (type 128, subtype 6) та числовим rate 0, без окремого
  IPv6-specific extended-community атрибуту type 25. Інші дії перевидаються як
  discard, якщо prefix бажаний, і відкликаються, якщо вже не потрібний.
  `sokol_flowspec_round_converged` перевіряє рівність обох повних prefix sets
  (owned і canonical discard) з wanted snapshot цього раунду. Публікується разом
  з observation; pending/failure/cancellation відкликають його до await. Health
  може бути 1, коли convergence 0. Це не рівність із latest intent, що міг
  змінитися під час раунду, не downstream enforcement і не нове право на дію.
- Порожній RIB закріпленого CLI — JSON-об’єкт `{}`. Порожній stdout, `null`,
  невалідні UTF-8/JSON чи непридатна структура шляхів не підтверджують відсутність.
  Кожен destination містить масив об’єктів шляхів; attrs і NLRI components — масиви.
  Peer-address перевіряється першим: відомий шлях піра не є локальною CLI-ціллю
  і виключається перед рештою перевірок. Для локальних шляхів типи атрибутів/components,
  standard communities, LocalID та source prefix/offset перевіряються перед
  класифікацією. GoBGP серіалізує порожню standard community як `null`; це
  дозволений порожній список, що не встановлює ownership tag. Відсутні peer-address і LocalID
  лишаються дозволеними, як у закріплених локальних capture; наявні мають коректний тип.
  Це мінімальний контракт полів класифікації, не повна JSON schema. Невідома чи
  неканонічна дія власного шляху лишається приводом до repair/withdrawal за R3.
  Непридатне початкове читання забороняє всі записи цього раунду; помилка повторного
  читання не скасовує вже прийняті CLI-операції, але не публікує нове спостереження.
- Власні правила позначаються community `64512:<node-id>` (`--flowspec-community`). Власним
  вважається лише локальний шлях з reported ID zero, цією community та одним повним source prefix
  (IPv6 offset 0). Шляхи пірів і чужі локальні шляхи не обираються для видалення.
  Відома колізія чужого локального шляху з NLRI потрібної операції пропускає тільки
  цю операцію до застосування квоти; інші відкликання й анонси продовжуються.
  Health лишається 0, попередні успішні кількості й час зберігаються. CLI не має compare-and-swap: конкурентний запис після читання може
  обійти цю перевірку. Спільні writers потребують серіалізації або окремих prefix namespace.
  GoBGP 4.9.0 NewDestination не копіює identifier у CLI JSON, тому `LocalID: 0`
  не доводить фактичний ID zero. Guard відмовляє лише за reported nonzero ID.
  Ownership community має належати одному writer: reuse нашого тега на hidden
  nonzero-ID шляху може збільшити owned count, хоча CLI ID-zero withdrawal його
  не прибере. Readback health не означає завершене відкликання.
- Кожен виклик GoBGP має таймаут, дочірній процес вбивається разом із задачею. При зупинці
  власні правила відкликаються в межах власного бюджету часу.

## Розглянуті варіанти

- **Пам'ять процесу.** Розходиться після рестартів; могла прибрати чуже правило.
- **Окремий gobgpd на вузол без маркування.** Не працює, коли кілька систем ділять один gobgpd.

## Наслідки

- Кожен вузол зі спільним gobgpd потребує своєї community та узгодженого володіння
  source-prefix namespace; сама community не ізолює CLI-записи.

## Перевірка

- `parse_rib` і `plan` у `flowspec.rs`.
- Smoke з двома gobgpd і справжньою BGP-сесією:
  - динамічний і статичний блоки анонсуються; блок, що сплив, відкликається;
  - зупинка відкликає власні правила, а правило іншої системи лишається;
  - після краху вузла його правило лишається, і наступний запуск прибирає застаріле та
    анонсує потрібне.

- Усі перевірки FlowSpec RIB у smoke використовують `scripts/flowspec-rib.sh`:
  невдале читання RIB — неперевірений результат, навіть коли CLI вивів частину відповіді.
  Відсутність запитується явно; помилка не перетворюється на успіх через заперечення.
  `scripts/test_flowspec_smoke.py` відтворює відмови на справжніх командах smoke.
  Це перевірка відображеного source prefix у текстовій відповіді закріпленого CLI,
  а не самостійний доказ ownership чи discard action (межа FLOWSPEC-S1).

- FLOWSPEC-R3 перевіряє rate-limit → discard, прибирання непотрібної неправильної
  дії й відмову при чужій локальній колізії на справжньому GoBGP 4.9.0, IPv4 та IPv6.
  `SOKOL_GOBGP_TEST_BIN` обов’язковий у canonical CI на x86 та ARM; локальний skip
  не є підтвердженням виконання. Деталі й межі — у DETECTOR_INVARIANTS.md.

- FLOWSPEC-R4 додає регресії для missing/null stdout, структури шляхів і полів
  ownership. Справжній GoBGP з чужим локальним шляхом та контрольоване спотворення
  тільки CLI read перевіряють відмову без записів для обох сімейств. Canonical CI
  вимагає окремий позитивний marker цієї перевірки в кожному сімействі.

FLOWSPEC-R6 (#136) додав переривання pending round при зміні wanted чи shutdown
і publication тільки змінених prefix sets. FLOWSPEC-R7 уточнює межу переривання:
RIB reads зберігаються, перед плануванням читається актуальний desired set, а
кожна queued/pending команда дозволена лише за актуальним membership її prefix.
Несуперечливі зміни зберігають той самий CLI future; недоречна команда скасовується,
перед наступним планом заново читається RIB. Post-write read також завершується;
convergence стосується sampled target; наступний раунд за зміненим intent починається
після 1 s паузи FLOWSPEC-R12.
FLOWSPEC-R8 зберігає решту початкової черги після скасування pending команди:
перед продовженням читає обидва RIB, перевіряє актуальний membership, потребу в
дії та нові чужі локальні колізії. Уже недоречна queued команда, яка ще не
починалась, просто пропускається. Заміну для скасованого prefix планує наступний
раунд; він потрібний і при поверненні desired set до початкового (ABA).
Непридатне свіже читання зупиняє подальші записи й зберігає попередні counts/time
із health 0. Це прогрес тільки в межах початкової черги до 64 різних prefixes
за придатних читань та успішних інших команд. Помилки CLI, backlog за квотою та
конкурентні writers лишаються межами; загальної гарантії справедливості немає.
До 64 скасувань можуть додати 128 read calls: груба верхня оцінка
`(2 + 64 + 128 + 2) × 5 s = 980 s` на live round, а не цільова latency.
Worker окремий від main tick, shutdown перериває цей раунд.
Shutdown true, already-true flag і закриття publisher переривають normal work та
починають наявну десятисекундну спробу cleanup; false не скасовує роботу.
Це не atomic revocation, rollback чи fence для remote RPC, який може застосуватися
після нового читання навіть при direct/exec CLI. Порожній cleanup read перед пізнім
add не гарантує відсутності правил після виходу. Wrappers мають `exec` CLI, бо
kill-on-drop завершує прямий child, не process tree. Скасована відповідь прийнятої
команди може не залишити ACK-аудиту. Збереження корисних calls не гарантує eventual
convergence при безперервній зміні того самого prefix; counts/time можуть
зберігатись при початку наступного раунду з health 0. Квота 64 є per-round,
не лімітом частоти між раундами. Ownership, policy і повноваження ті самі.


FLOWSPEC-R9 продовжує початкову чергу й після помилки окремого CLI запису:
відмова, timeout чи помилка запуску не означають відсутності ефекту. Перед
наступною командою worker заново читає обидва RIB і перевіряє актуальний membership,
потребу в дії та чужі локальні колізії. Непридатне recovery-читання зупиняє записи.
Навіть коли наступні команди успішні або відмовлена команда вже мала ефект,
раунд повертає помилку: попередні counts/time зберігаються, health/convergence — 0.
Лише наступний успішний раунд публікує відновлення. За придатних читань діагностика
містить першу помилку запису, кількість невдалих команд і пропущених колізій; невдалий запис не отримує ACK-аудиту.
Непридатне recovery або final read повертає власну помилку читання одразу.
Той самий шлях використовується у cleanup, але його бюджет лишається 10 секунд.
До 64 сумарних скасувань або помилок дають до 128 додаткових read calls;
оцінка 980 секунд стосується також fixed-target раунду з помилками, а не його
cleanup deadline. Квота, withdrawal-first, політика й повноваження не змінені.
Це прогрес решти поточного плану за придатних читань, не загальна справедливість:
непридатні reads, довгі calls, backlog за квотою та конкурентні writers лишаються
межами. FLOWSPEC-R10 витримує щонайменше секунду після завершення невдалого
normal round, перш ніж знову дозволити reconciliation. Накопичені timer ticks,
зміни наміру й false shutdown notifications не скорочують і не перезапускають
паузу. Наступний раунд бере актуальний desired set. True shutdown або закриття
будь-якого publisher перериває паузу й одразу починає окремий bounded cleanup;
його 10-секундний бюджет і власні 500-мс error pauses не змінені. До FLOWSPEC-R12 успішні раунди
й перепланування supersession не отримували цієї затримки. Це мінімальна пауза
між невдалим normal round і наступним, не ліміт calls/second: одна черга все ще
може містити 64 записи та їх recovery reads. Remote RPC може мати пізній ефект;
читання не є rollback чи fence, CLI-ACK audit не є повною історією ефектів.


FLOWSPEC-R11 ротує prefixes усередині withdrawal та announce між раундами.
Два worker-local курсори тримають останній розглянутий prefix кожного класу;
після нього новий відсортований набір обходиться по колу. Вони не кешують RIB,
дозвіл чи результат дії. Worker зберігає їх після успіху, помилки й supersession
та використовує у bounded cleanup. Курсор рухається при розгляді конкретного
запису перед cancellable роботою; рання відмова readback не перескакує нерозглянуту
решту плану. Непридатне початкове читання не змінює курсори. При restart вони
скидаються; жодна нова черга не використовується без придатних RIB reads.
Квота 64, withdrawal-first і всі перевірки актуального membership, потреби та
чужих колізій лишаються. Публічний one-shot `plan` зберігає відсортований початок.
Це умовна можливість спроби для скінченного стабільного набору всередині класу,
не гарантія ефекту: якщо withdrawals постійно займають всю квоту, announces
чекають. Непридатні reads, нескінченна зміна наборів, повільні calls і restart
можуть перешкодити прогресу; cleanup має той самий 10-секундний бюджет.

## FLOWSPEC-R12 — витрати роботи й спостережений поступ

Worker більше не накопичує interval ticks: після кожного завершеного normal round
витримує одну монотонну паузу 1 s. Успіх CLI, відсутність ефекту, помилка та
supersession споживають той самий дозвіл на раунд. Зміни wanted і false shutdown
не скорочують і не перезапускають паузу; наступне читання знову бере актуальний
intent. Перша спроба не затримується. True shutdown та закриття будь-якого publisher
одразу переривають normal work/паузу й починають cleanup. Cleanup зберігає власний
deadline 10 s та cursor; після кожного непорожнього успішного раунду або помилки
чекає 500 ms усередині deadline. Підтверджений порожній owned RIB завершує його
без паузи. Так no-effect success не перетворюється на гарячий цикл. Ціна цього
обмеження — менше withdrawal batches за ті самі 10 s, ніж при негайних повторах
успішних раундів; залишкові правила потребують окремої перевірки RIB.

Операційна ціна лишається конкретною: до 64 кандидатів за раунд, ліміти CLI calls
і наведені вище read/recovery allowances. Це не універсальна ATP-валюта, не
глобальний calls/second чи memory bound, не довічна квота daemon і не стійкий
до restart облік. Worker-local паузи не обмежують іншого writer. Shutdown cleanup
має незалежний дозвіл; припинення child process не відкликає прийнятого RPC.

`sokol_flowspec_round_progress`: `1` — між initial/final reads раунду спостережено
строге зменшення набору невиконаних вимог до sampled wanted без нових; `0` — такого
поступу не спостережено; `-1` — немає придатного завершеного виміру. Вимоги
розрізняють видалення owned prefix поза wanted та встановлення canonical discard
для wanted prefix. Порівнюються ідентичності й типи дій, а не лише counts:
перестановка однакової кількості prefixes або менша кількість із новою помилкою
не є поступом. Pending/failure/cancellation відкликають значення до першого await;
повні initial/final reads одного раунду визначають вимір. Ефект не приписується
командам цього раунду: пізній раніший RPC або інший writer також можуть зменшити
розбіжності. Failed CLI навіть після
реального ефекту не публікує нового виміру. Уже досягнута ціль може мати progress 0
і convergence 1. Інший sampled target, міжраундовий поступ, latest intent, причини
застою, неминуче завершення та upstream enforcement цим не встановлюються.
Перевіряйте health, convergence і age разом; універсального stall-порога немає.

Перенесено дисципліну бюджету Sigma-Glyph (додатна ціна дії, перевірка допустимості
перед дією, окрема причина завершення) і Black-Heart (накопичені витрати при resume,
resource exhaustion не є semantic refutation, null measurement не є нулем).
Це незалежна реалізація для мережевих спроб: на відміну від незарядженої невдалої
редукції, мережеві помилки також витрачають роботу. Lean-теореми Sigma-Glyph про
терми й ATP не доводять властивостей цього Rust worker. Джерела перенесення:
Sigma-Glyph `f46a7460b4ca2731899a61725cb5cc15ff0bac46`, `impl/sigma_glyph.py`;
Black-Heart `63649b8`, `glyph.py`, `scoped_admission.py`, `library_interaction.py`.

Перевірки: `successful_no_effect_rounds_wait_despite_intent_churn`,
`successful_no_effect_rounds_wait_despite_overdue_ticks`,
`superseded_success_shares_the_work_pause`,
`successful_no_effect_cleanup_waits_and_then_recovers`,
`round_progress_requires_strict_identity_and_action_improvement`,
`progress_distinguishes_unmeasured_from_zero_and_requires_health` і
`live_gobgp_work_budget_paces_success_and_cleanup_with_truthful_progress`.
Перші чотири виконувані регресії компілюються на base `c62437f` і падають на
кількості ранніх спроб. Live test використовує pinned GoBGP 4.9.0 для обох сімейств:
no-effect add/delete, supersession, справжнє відновлення, cleanup, true shutdown та
обидва закриті publishers; foreign paths перевіряються окремо. Раннє завершення
cleanup у stop-сценаріях є результатом контрольованого усунення no-effect fault,
не гарантією виконання під постійною відмовою. CI вимагає positive marker кожної
сім'ї, повні native x86/ARM jobs і незмінені frozen Stargate checks.

## FLOWSPEC-R13 — початковий намір після відновлення

Main створює FlowSpec watch-channel зі snapshot `BlockTable::active_ips()` під
тим самим lock, до spawn worker. Static configuration та state restore вже
застосовані. Попереднє початкове `{}` вигадувало відсутність блоків: worker міг
прочитати RIB і відкликати ще потрібні owned правила до першого main tick,
а пізніша публікація знову їх анонсувала. Це scheduling-dependent вікно відтворено
на фактичному worker і GoBGP 4.9.0 без main-loop публікацій.

Джерело залишається застосованим набором, як у наступних tick publications:
не всі durable claims і не число успішних restore. Відхилені політикою,
прострочені та pending kernel-map additions не анонсуються. Дійсно порожній
applied set усе ще відкликає старі owned правила. Чужі локальні paths, shutdown,
observe-mode заборона worker, quota/cursors та pacing не змінюються.

Snapshot не є атомарною угодою між BlockTable, RIB і upstream. Зміни після його
створення потрапляють у звичайну публікацію; цей крок не робить її миттєвою.
Не гарантується відсутність усіх можливих флапів, новий durable intent, успішне
state restore чи upstream enforcement. Failed restore лишає наявну DEGRADED
семантику: старт із тим applied set, який вузол реально має.

Регресії `startup_worker_keeps_restored_blocks_and_announces_static_before_any_tick`,
`startup_worker_with_no_applied_blocks_withdraws_stale_owned_rules` та
`live_gobgp_startup_preserves_applied_restoration_before_any_tick` використовують
фактичні BlockTable serialization/restore, production channel initializer і worker;
лише kernel-map operations у unit tests замінені. Live test перевіряє обидві
сім'ї, retained/static, refused/expired/unapplied/stale, порожній applied set,
наступний intent, cleanup та незмінний foreign RIB. CI вимагає обидва positive
markers. Production XDP smoke додатково перезапускає справжній вузол із тим самим
state file, перевіряє XDP/RIB/HTTP і записує worker CLI calls, щоб delete/re-add
не приховався за пізнішим успіхом; fresh-state stale cleanup лишається окремим.

## Коли переглянути

Коли знадобиться інший BGP-стек або спільна політика анонсів для кількох систем.
