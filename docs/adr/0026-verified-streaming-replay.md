# ADR-0026. Replay споживає перевірений префікс, із обмеженим звітом

**Статус:** реалізовано; нова межа записана як `UNSIGNED_INTENT` у пропозиції REPLAY-B1.
Формальне прийняття й re-pin залишаються за власником (ADR-0023/0024).
**Дата:** 2026-10-11. Доповнює ADR-0016 і ADR-0021.

## Контрприклади

На базі `a06be0c` replay перевіряв весь chain, потім повторно відкривав сегменти й
збирав усі payload у Vec. Підміна активного сегмента при другому open на внутрішньо
валідний, але не з'єднаний із попереднім сегмент давала CLI 0. Окремо 257 розбіжностей
утримували 257 прикладів, а 65 запусків чужих збірок — 65 причин. Обірваний хвіст після
відтвореного рішення давав 0. Відтворення й вимір — у
[датованому результаті](../status/2026-10-11/REPLAY-RESULT.uk.md).

## Реалізація

`common::audit_log::visit_chain` читає кожен сегмент один раз і віддає запис лише після
перевірки його chain і початкового зв'язку сегмента. `verify_chain`, `check_witnesses` та
`replay_file` користуються цим шляхом. Callback обчислює лише тимчасовий результат:
пізня помилка повертає Err, і споживач не публікує verdict. Не можна застосовувати зовнішні
незворотні ефекти всередині callback, покладаючись на перевірку решти журналу.

Довжина й фінальна metadata беруться з відкритого descriptor. У споживача потрапляють
лише записи, що закінчуються в межах початкової довжини цього файла. Завершення torn record
через цю межу або зменшення файла відмовляє scan як Unverified. Дописування після вже
повного префікса не продовжує scan нескінченно. Заміна pathname не підміняє відкритий файл. Зміна довжини закритого ротованого
сегмента під час scan теж відмовляє перевірку як Unverified.

`ChainSummary` містить first_seq, next_seq, head, число сегментів і trailing_bytes.
Replay повертає цей summary і друкує VERIFIED PREFIX перед кінцевим підсумком.
Torn active tail допускається низькорівневою перевіркою, як раніше, але replay має
INCOMPLETE TAIL і не повертає 0. Невалідний UTF-8 огороджує залежні рішення до нового
придатного NODE_START і рахується окремо як NON-TEXT RECORDS, запобігаючи CLI 0.
Невідомий тип запису не видають за одну відому decision і не підміняють lossy текстом.

Сегмент із start_seq 0 мусить мати previous chain із нулів, як визначено форматом
record 0. Внутрішньо узгоджені records на чужому genesis seed відхиляють reader,
writer reopen, verify і witness comparison. Сегмент вище нуля може мати будь-який
previous head: попередню частину може бути прунено. Це перевіряють
`a_zero_sequence_segment_cannot_replace_the_genesis_chain` на реальних bytes та
Kani proof `audit_log::proofs::a_zero_sequence_segment_has_the_fixed_genesis_chain` для всіх входів
pure predicate, який викликає decoder. Перевірка genesis не автентифікує весь журнал.

## Ресурсний профіль

- До 4 096 ротованих сегментів у inventory; наступний файл відмовляє читання переліку
  до push. Межа діє також у writer resume/prune, які використовують той самий inventory.
  Це operational ceiling, не автоматичне видалення зайвих файлів; велике `--audit-keep`
  може з часом перевищити його. Типове значення 10 лишається в межах.
- До 128 прикладів MISMATCH; повний mismatch_count рахується незалежно.
- До 32 префіксів причин INSUFFICIENT; додаткові рішення мають окремий лічильник.
- До 512 UTF-8 bytes на збережене діагностичне поле. Це префікси, не повний forensic dump;
  різні довгі причини можуть мати однаковий префікс і об'єднаний лічильник.
- Втрата деталей явна: DETAILS OMITTED / additional reason categories omitted.
  Кінцеві totals і код виходу використовують повні лічильники.

У пам'яті лишаються один payload до MAX_PAYLOAD, обмежена BlockTable та bounded report,
а не всі байти журналу. Це не межа CPU чи тривалості читання довільно великого статичного
журналу, і не кваліфікація фізичної NIC.

## Межі свідчення

Summary ідентифікує спожитий chain prefix. Він не засвідчує автора, не є підписом власника,
не доводить повноту журналу і не є атомарним snapshot файлової системи. Файли можуть
відкритися в різний час; переписування всієї узгодженої chain вимагає зовнішнього якоря,
як раніше (ADR-0021/0022). Часткові callback результати не мають самостійної сили.

## Перевірка

`chain_consumers_validate_the_next_segment_before_offering_it` підміняє наступний сегмент
на внутрішньо валідний під час scan; його записи не доходять до callback.
`a_scan_keeps_the_open_file_identity_and_initial_complete_prefix` перевіряє append та
pathname replacement. `shortening_or_completing_a_torn_record_during_scan_is_unverified`
перевіряє shrink і completion за межі початкової довжини.
`a_sealed_segment_cannot_grow_while_consumers_scan_it` відмовляє зміну закритого сегмента.
`retained_segment_inventory_refuses_limit_plus_one` перевіряє exact/+1 inventory.
`late_chain_failure_discards_the_tentative_file_replay` перевіряє відмову після раннього match.
`mismatch_examples_are_bounded_without_stopping_replay`,
`foreign_build_diagnostics_cannot_grow_with_each_run`,
`retained_diagnostics_preserve_counts_and_utf8_at_the_exact_budget` та
`cli_totals_and_omission_markers_agree_with_the_complete_input` перевіряють bounds і повні
лічильники, включно з реальним subprocess CLI. `a_torn_or_non_text_tail_never_certifies_a_complete_replay`
перевіряє неповний/non-text кінець у справжньому chained file.

Rehearsal теж перевіряє належність свідчення: Restore failed шукається лише у journal
поточного systemd InvocationID, з коротким очікуванням видимості й повним читанням producer.
Старий запис, невдале/часткове читання чи некоректний id не є успіхом. Свідок:
`CurrentJournal.test_restore_failure_requires_current_invocation_and_drains_the_producer` у
`scripts/test_runbook_preflight.py`.

Cargo-mutants не виконує cfg(kani) harness у native test binary. Вузьке виключення
цього harness не виключає runtime predicate valid_segment_start; його мутації лишаються
в sweep. Умова ==/!= у самому harness окремо перевірена через Kani і відхилена.
Непорожність і адекватність тверджень доказу лишаються обов’язком рев’ю.
