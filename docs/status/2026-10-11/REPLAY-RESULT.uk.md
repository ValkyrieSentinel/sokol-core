# Audit/replay: контрприклади й результат

Дата: 2026-10-11. База: `a06be0c7e41f95bcd30da034b3d663f8df96d4cb`.
Це датоване свідчення та пояснення, не прийняття нового контракту.

## Відтворення старої поведінки

Два нові тести на незміненій реалізації бази впали саме на assert:
`mismatch_examples_are_bounded_without_stopping_replay`: 257 != 128;
`foreign_build_diagnostics_cannot_grow_with_each_run`: 65 != 32.
Проміжний streaming шлях до виправлення torn-tail дав assert 0 != 2 у
`a_torn_or_non_text_tail_never_certifies_a_complete_replay`.

Реальний pre-change CLI (`--version`: build local-upgrade) у Linux ARM64 лабораторії
читав active file двічі. [open64 shim](replay_swap.c) замінив файл при другому відкритті
на внутрішньо валідний сегмент зі зміненим previous head і заново обчисленим record hash.
Старий CLI повідомив `1 reproduced` і exit 0, хоча join із попереднім сегментом був broken.
Звичайне читання без shim також мало 0; це позитивний baseline.

Проміжний новий CLI відкрив active file лише один раз; hook другого open не відбувся.
Коли той самий неправильний сегмент уже лежав на диску, новий CLI повернув 2 / NOT REPLAYED.
Регресія `chain_consumers_validate_the_next_segment_before_offering_it` виконує цю підміну
під час callback реального reader і вимагає Broken без передачі записів поганого сегмента.

Додатковий контрвектор для проміжного streaming коду на macOS (`common` без Aya):
`a_sealed_segment_cannot_grow_while_consumers_scan_it` одержав Ok замість Unverified,
коли callback дописав bytes у закритий ротований сегмент. Після перевірки metadata
відкритого descriptor усі 32 common tests пройшли. Це scoped filesystem/unit перевірка,
не підтримка Sokol на macOS.

Подальший `common` byte vector виявив ненульовий previous head у SALS start_seq 0,
який проходив verify попри визначений форматом нульовий predecessor record 0.
`a_zero_sequence_segment_cannot_replace_the_genesis_chain` впав на assert verify.is_err.
Додано перевірку genesis в decoder, позитивні zero-genesis/pruned-prefix cases, відмову
writer/witness API без зміни файлів, і Kani proof pure predicate.

## Ресурсний пробник

[Fixture](replay_fixture.rs) пише 1 024 payload по 64 KiB між NODE_START та рішенням:
67 166 502 bytes chained file. Обидва CLI відтворили одне рішення.
Одноразовий `/usr/bin/time` на Linux ARM64:

| Артефакт | Peak RSS KiB | elapsed s |
|---|---:|---:|
| pre-change | 70 272 | 0.12 |
| проміжний streaming | 4 992 | 0.05 |

SHA256 виконаних артефактів:
- pre-change: `d3d4252df9f48641552348059af5eb2a10a3a51cdc821d79b9982a740f625f76`;
- проміжний streaming: `fa8cbfad71394a551d36dcb72e69d3bbab4257d8f06716d7828b4b466d110235`.

Ці артефакти мають явний build local-upgrade, а не самопідписану прив'язку до commit.
Це scoped лабораторний probe; наведений hash і спостережена поведінка не є зовнішньою
build attestation. Вимір не встановлює production RSS/SLO, асимптотику часу всього ядра
або фізичну NIC. Нові unit та mutation результати записуються нижче окремо.

Відтворення на тимчасовому Linux checkout бази/зміненої версії: зберегти pre-change CLI
поза target, скопіювати replay_fixture.rs у тимчасовий common/examples/replay_fixture.rs,
зібрати його `cargo run --locked --release -p common --example replay_fixture`;
зібрати shim `cc -shared -fPIC replay_swap.c -ldl -o /tmp/sokol-replay-swap.so`.
Встановити SWAP_TARGET=/tmp/sokol-replay-race/audit.sntl,
SWAP_ALTERNATE=/tmp/sokol-replay-race/alternate та LD_PRELOAD=/tmp/sokol-replay-swap.so
для CLI `--replay /tmp/sokol-replay-race/audit.sntl`. Fixture directory треба очистити
перед повторним створенням. Для пам'яті додати fixture argument 1024 і читати large.sntl.
Build context має збігатися з CLI: fixture використовує local-upgrade. Видалити
тимчасовий common/examples probe перед CI; він не є новою production командою.

## Проміжні перевірки, які не є фінальним CI

Tree `fbbec8cc33ca607c5430adf82928e25fad0f613b` до genesis delta:
562 Rust passed / 3 ignored, Clippy, Python regressions, 4 Kani harnesses;
changed-line sweep: orchestrator 74 caught + 1 timeout, common 24 caught + 3 unviable,
0 missed. Дев'ять умов друку, які пропустив перший sweep, спіймав subprocess CLI свідок;
вони не виключені з мутацій. XDP smoke і demo пройшли, але runbook rehearsal мав одну
невдалу перевірку journal, тож цей повний запуск НЕ є green CI.

Journal-повідомлення Restore failed було видиме пізніше. Причину саме цього live failure
не встановлено. Окремий assertion-red fake journal producer відтворив статус 141 замість
0 через grep -q / pipefail; не обмежений invocation пошук також міг читати старий запуск.
Новий predicate у runbook-rehearsal прив'язує journal до поточного systemd InvocationID,
drain-ить producer, відмовляє partial/failed reads і коротко очікує видимість журналу.
`test_restore_failure_requires_current_invocation_and_drains_the_producer` перевіряє
large current, stale-only, unreadable, partial-current і malformed-id cases. Усі чотири
preflight/journal Python tests пройшли. Це тест контрольованих процесів, не systemd demo.

Перший full CI раніше відмовив на cited evidence: shared Cargo cache утримав старий
common artifact після tar зі старішими timestamps. Після clean --release common/orchestrator
новий sealed-segment witness виконався; старий кешований результат не зараховується.

Mixed helper реально виконав 11 свідків із hash-checked private copy tree fbb і повторив
їх як REPLAYED_PASS. Input snapshot:
`sha256:e9f424ce0e2d760d2ecfdc11f3141a389dd992a4c2e2ea940edc345c7ad7fac0`.
Context 4 675 bytes, correspondence UNSIGNED_PROPOSAL, initial execution UNKNOWN.
Після genesis/document delta цей історичний report є STALE, а не доказом нового snapshot.
33 common tests пройшли на macOS; новий genesis Kani harness окремо пройшов у Linux:
0 із 16 checks failed. Ці scoped результати не замінюють фінальний full CI.

Окремий sweep після genesis delta мав orchestrator 74 caught + 1 timeout,
common 32 caught + 3 unviable + 2 missed. Обидва survivors були в самому cfg(kani)
harness, який native cargo test не виконує, а не в runtime predicate. Умовний mutant
==/!= окремо відхилено cargo kani --harness: 2 із 16 checks failed. Вузьке виключення
цього verification harness залишає runtime valid_segment_start у sweep. Видалення
тверджень із harness може бути vacuous proof, тому їх непорожність і адекватність
залишаються обов’язком рев’ю; це не оголошено еквівалентним доказом.

## Перевірка фінального snapshot

Цей файл входить до input snapshot; execution reports зберігаються поза checkout,
щоб запис результату не змінював його власний вхід. Фінальні local/remote CI результати
й свіже виконання публікуються в PR review з прив’язкою до exact head. Наведені вище
проміжні результати не замінюють їх і не є поточним глобальним статусом.

У підтримуваному Linux checkout:

```sh
scripts/local-ci.sh
python3 scripts/witness-pin.py check
python3 scripts/contract-task.py context REPLAY-B1 --proposal docs/contracts/proposals/REPLAY-B1-8006a180d409.proposal.json
report_dir=$(python3 scripts/contract-task.py run REPLAY-B1 --proposal docs/contracts/proposals/REPLAY-B1-8006a180d409.proposal.json) &&
python3 scripts/contract-task.py verify "$report_dir/report.json" --replay
```

Native set має 12 свідків із common/orchestrator. Потрібні compiler matches, successful
named executions і fresh REPLAYED_PASS; matching unsigned report без replay лишає execution
UNKNOWN. Kani, full CI і deployment qualification перевіряються окремо.

Старі 40 інваріантів і 101 witness match owner pins; REPLAY-B1 лишається UNSIGNED_INTENT.
Прийняття/re-pin є дією власника (AGENTS.md, ADR-0023/0024).
