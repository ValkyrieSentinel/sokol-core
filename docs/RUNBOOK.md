# Runbook оператора

Для людини, що встановлює й обслуговує вузол Sokol-Core, без автора поруч. Кожна команда тут
перевіряється в `scripts/xdp-smoke.sh` або береться з `deploy/`. Де поведінку не перевірено, це
сказано. Шляхи — як у `deploy/sokol-orchestrator.service`.

Весь шлях від встановлення до пакета для підтримки проганяє `scripts/runbook-rehearsal.sh` на
чистому systemd-хості (див. кінець документа).

Перевірені середовища — у [SUPPORT.md](SUPPORT.md). Чому система поводиться саме так — у
[ARCHITECTURE.md](../ARCHITECTURE.md) і [ADR](adr/README.md).

Скорочення для керуючого сокета (усі команди нижче):

```shell
ctl() { printf '%s\n' "$1" | sudo nc -U -q1 /run/sokol/control.sock; }
metric() { curl -s http://127.0.0.1:9469/metrics | grep "^$1"; }
```

## 1. Встановлення

```shell
cd ebpf && cargo build --release --locked && cd ..
cargo build --release --locked
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sokol
sudo groupadd --system sokol-ipc     # детектори: IPC-сокет
sudo groupadd --system sokol-ops     # оператори й дашборд: керуючий сокет
sudo install -m 0755 target/release/orchestrator /usr/local/bin/sokol-orchestrator
sudo install -m 0755 target/release/monitor /usr/local/bin/sokol-monitor
sudo install -m 0644 deploy/sokol-orchestrator.service /etc/systemd/system/
sudo install -d -o sokol -g sokol -m 0700 /var/lib/sokol   # як StateDirectory; потрібен уже в §2
sudo install -d -m 0755 /etc/sokol
```

`/etc/default/sokol`:

```shell
SOKOL_ARGS=--interface eth0 --node-id 1 --peers-file /etc/sokol/peers.json \
  --seed-peer 10.0.0.2:7946 --metrics-bind 127.0.0.1:9469 \
  --never-block 203.0.113.0/24
```

- `--node-id` унікальний у меші.
- `--never-block` — мережі операторів і бастіонів; адреси самого вузла, його шлюзи,
  seed-піри й endpoint'и WireGuard-пірів захищені й так.
- Метрики вмикаються лише з `--metrics-bind`.
- Синхронізація часу (chrony або NTP) обов'язкова.

## 2. Ключі й піри

```shell
sudo -u sokol /usr/local/bin/sokol-orchestrator --key-file /var/lib/sokol/node.key --print-public-key
```

Виводить `mldsa65:<hex>`; файл ключа створюється при першому запуску (`0600`). Зберіть ключі
всіх вузлів у `/etc/sokol/peers.json` на **кожному** вузлі (меш має бути повним). Файл
потрібен до старту служби; перший вузол, поки інших немає, стартує з `[]`.

```json
[
  { "node_id": 2, "public_key": "mldsa65:<hex вузла 2>" },
  { "node_id": 3, "public_key": "mldsa65:<hex вузла 3>" }
]
```

## 3. Перший старт і перевірка

```shell
sudo systemctl enable --now sokol-orchestrator
journalctl -u sokol-orchestrator -n 50 --no-pager
```

| Що перевірити | Як | Очікується |
|---|---|---|
| Версія й збірка | `metric sokol_build_info` | `version=…,build=<commit>` |
| Здоров'я | метрики `*_healthy`, `*_ok` з §4; дашборд показує `MODE` з heartbeat | усі `1`, `MODE=NORMAL` |
| XDP на інтерфейсі | `ip -d link show eth0` | `prog/xdp` |
| Піри з'єднані | `metric sokol_p2p_active_peers` | кількість інших вузлів |
| Бани оператора | `ctl LIST_BANS` | `OK <n> …` |
| Ланцюжок аудиту | `sudo sokol-monitor --verify /var/lib/sokol/audit.log` | `OK …` |
| Захищені адреси читаються | `metric sokol_protected_refresh_ok` | `1` |

## 4. Метрики, за якими стежити

| Метрика | Тривога, якщо | Значення |
|---|---|---|
| `sokol_audit_healthy` | `0` | аудит не пишеться (диск, права); захист працює (ADR-0005) |
| `sokol_state_healthy` | `0` | файл стану не пишеться або зміна чекає > 5 с (ADR-0004) |
| `sokol_state_pending_seconds` | росте | диск повільний або завис |
| `sokol_state_restore_ok` | `0` | стан при старті не відновився, див. §5.4 |
| `sokol_protected_refresh_ok` | `0` | адреси хоста не читаються; захищено останні відомі |
| `sokol_blocks_pending` / `…_oldest_seconds` | > 0 довго | карта ядра не приймає записи (переповнена) |
| `sokol_blocks_active` vs `sokol_blocks_capacity` | > 80 % | наближається ліміт 65 536 |
| `sokol_p2p_active_peers` | менше очікуваного | див. §5.5 |
| `sokol_mesh_envelopes_rejected_total{reason="stale_timestamp"}` | росте | годинник піра й цього вузла розійшлися понад 30 с (NTP) |
| `sokol_clock_steps_total` | зросла | годинник вузла крокував на `sokol_clock_last_step_seconds`. Чинні блоки зберігають тривалість (ADR-0017), але якщо годинник тепер розходиться з пірами понад 30 с, вузол випадає з мешу (див. `stale_timestamp`) |
| `sokol_claims_waiting` | > 0 довго | пір видав більше рішень, ніж дозволяє його конверт (`--peer-max-active`, 16 384, ADR-0007): решта чекає на слот. Через це кількість блоків на вузлах різниться, хоча меш справний |
| `sokol_mesh_broadcasts_dropped_total{class="urgent"}` | росте | лінк до піра не встигає за заявками |
| `sokol_mesh_handshake_timeouts_total` | швидко росте | хтось відкриває з'єднання й мовчить |
| `sokol_tick_seconds_max` | > 0,5 | обслуговування таблиці сповільнюється |
| `sokol_xdp_events_lost_total` | росте | orchestrator не встигає читати події ядра: кільце повне, події (не блоки) губляться |
| `sokol_xdp_events_malformed_total` | > 0 | XDP-програма й orchestrator розходяться в розкладці подій (ADR-0015): бінарник зібрано неправильно |
| `sokol_block_outcomes_total{effect="none"}` | частка велика | блоки нічого не відкидають: `sudo sokol-monitor --outcomes /var/lib/sokol/audit.log` покаже, які детектори й правила (ADR-0014) |

Будь-яка з перших п'яти причин переводить вузол у `MODE=DEGRADED`. Захист при цьому працює.

**Готові алерти й дашборд:**
- `deploy/prometheus/sokol-alerts.yml` — 16 правил за цією таблицею, з тестами
  `promtool test rules sokol-alerts.test.yml`;
- `deploy/prometheus/prometheus.yml` — приклад збору. Метрики без автентифікації, тож
  `--metrics-bind` лише на приватну адресу (WireGuard, мережа керування);
- `deploy/grafana/sokol-dashboard.json` — імпорт у Grafana. Ряди: стан вузлів, фаза 0
  («відкинув би»), рішення й наслідки, меш, ресурси.

## 5. Інциденти

### 5.1 Помилковий блок

```shell
ctl "UNBAN_IP:198.51.100.7"       # знімає всі відомі рішення про ціль, і для пірів теж, локально
ctl FLUSH_BANS                    # усі динамічні блоки (детектори, меш); бани оператора лишаються
ctl FLUSH_ALL                     # і бани оператора; --block лишається
```

- Власні рішення детектора знімаються на всьому меші; чужі — лише на цьому вузлі.
- Нове виявлення тієї самої адреси — нове рішення, і воно заблокує знову.
- Що зробив знятий блок, видно в аудиті: `BLOCK_OUTCOME|IP:…|Dropped:…|Seconds:…`.
- Щоб адреса не блокувалась ніколи, додайте її в `--never-block` і перезапустіть службу.

### 5.2 Вузол заблокував би себе чи шлюз

Політика цього не дозволяє: адреси вузла й шлюзи перечитуються кожні 2 с (ADR-0012). Блок
адреси, що щойно стала своєю, знімається протягом 2 с (`BLOCK_RELEASED_PROTECTED` в аудиті).
Зовнішні адреси WireGuard-пірів захищаються автоматично (потрібен інструмент `wg`); адреси в
тунелі додайте в `--never-block`.

### 5.3 `MODE=DEGRADED`

| Метрика в `0` | Причина | Дія |
|---|---|---|
| `sokol_audit_healthy` | диск заповнений, права, збій запису | звільнити місце або виправити права; відновлюється само; втрати позначені `AUDIT_LOST` |
| `sokol_state_healthy` | запис стану не вдається або висить > 5 с | див. `sokol_state_pending_seconds` і журнал `[State]`; відновлюється само |
| `sokol_state_restore_ok` | стан не відновився при старті | §5.4 |
| `sokol_protected_refresh_ok` | не читаються адреси хоста | журнал `[BlockPolicy]`; відновлюється само |

### 5.4 Стан не відновився при старті

У журналі — `[State] Restore failed: …; bytes kept at …`. Вузол працює, але без попередніх
власних рішень і знять. Байти збережено в `<state-file>.corrupt[.N]`.

1. Подивіться причину: пошкоджений файл, права або інша схема («state schema N, this build
   reads M»; міграцій немає, ADR-0004).
2. Якщо стан можна повернути, зупиніть службу, поверніть правильний файл на місце й запустіть.
3. Якщо ні, прийміть втрату. Бани оператора й зняття тоді треба відновити вручну.

```shell
ctl ACCEPT_STATE_LOSS             # "OK state loss accepted"; вузол виходить із DEGRADED
```

### 5.5 Пір не з'єднується

Шукайте в журналі обох вузлів:

| Запис | Причина | Дія |
|---|---|---|
| `Rejected envelope … UnknownSender` | ключа піра немає в `peers.json` | додати ключ і `ctl RELOAD_PEERS` |
| `Rejected envelope … BadSignature` | ключ у `peers.json` не той | звірити `--print-public-key` піра |
| `Rejected envelope … StaleTimestamp` | годинники розійшлися > 30 с | налаштувати chrony/NTP |
| `has only a legacy Dilithium3 key` | у `peers.json` старий ключ v1 | новий `mldsa65:` ключ піра (README, оновлення v1→v2) |
| `pre-versioned mesh protocol` / `no common mesh protocol version` | пір іншої версії | оновити пір |
| `no handshake within 5s` | з'єднання мовчить | мережа, файрвол (TCP 7946) |

Меш сходиться сам: дайджести кожні 15 с, знімок — не частіше разу на 5 с на піра.

### 5.6 Адаптер детектора не доставляє

- Журнал адаптера: `alerts queued, retrying` (Suricata) чи `decisions queued, retrying`
  (CrowdSec) означає, що вузол недоступний, а сигнали чекають у черзі (до 10 тис. для
  Suricata, 100 тис. для CrowdSec).
- Suricata з `--cursor-file` після рестарту продовжує з місця зупинки. Алерти, старші за
  10 хв, пропускає.
- Повтори безпечні: вузол відповідає `OK duplicate`.

## 6. Ключі: ротація, відкликання, компрометація

- **Ротація без простою.**
  1. Згенеруйте новий ключ: `--key-file /var/lib/sokol/node.key.new --print-public-key`.
  2. На всіх пірах пропишіть обидва ключі: `"public_keys": ["<старий>", "<новий>"]`, потім
     `ctl RELOAD_PEERS`.
  3. Замініть `node.key` новим і перезапустіть вузол.
  4. Приберіть старий ключ з усіх `peers.json` і знову виконайте `RELOAD_PEERS`.
- **Відкликання вузла.** Приберіть його з `peers.json` на всіх вузлах і виконайте
  `ctl RELOAD_PEERS`. Його заявки перестають діяти одразу (`revoked`), з'єднання
  закривається на першому ж повідомленні.
- **Зіпсований `peers.json`.** Помилка синтаксису, помилка в ключі чи дублікат не міняють
  чинну довіру: відповідь `ERR …; previous trust store kept`.
- **Компрометація вузла.** Відкличте його (див. вище), потім перевірте аудит інших вузлів:
  `MESH_BLOCK_HELD` показує, що його заявки обмежував конверт чи кворум (ADR-0007).

## 7. Оновлення й відкат

Релізу ще немає, тож формати можуть змінюватися без сумісності; кожна зміна описана в ADR.

- Бінарник оновлюється як звичайно: встановити й `systemctl restart`. Перевірте
  `sokol_build_info`.
- **Відкат** — це бінарник, `node.key`, `peers.json` і файл стану **разом**. Файл стану іншої
  схеми не відновлюється (§5.4).
- Перехід протоколу мешу v1→v2 виконується в одне вікно на всіх вузлах; локальний захист
  при цьому працює (README).

## 8. Аварійно зняти фільтр

```shell
sudo systemctl stop sokol-orchestrator
ip -d link show eth0              # prog/xdp зник: трафік іде без фільтра
```

Smoke перевіряє, що зупинка служби (і навіть SIGKILL процесу) знімає XDP-програму з
інтерфейсу. Бани оператора збережені у файлі стану й повернуться при наступному старті.

## 9. Пілот: фаза 0 — тінь

```shell
SOKOL_ARGS=… --enforce observe      # у /etc/default/sokol, потім systemctl restart
```

- Вузол ухвалює всі рішення й пише аудит, але його рішення **ніде не відкидають
  пакетів** (ADR-0018). Власні заявки не йдуть у меш, FlowSpec не анонсується навіть із
  `--flowspec-gobgp`, телеметрія не заявляє атаку. Заявки пірів вузол приймає, але не
  відкидає за ними.
- Що він відкинув би, видно тут:
  - `metric sokol_xdp_observed_packets_total` — за причинами;
  - `sudo sokol-monitor --outcomes /var/lib/sokol/audit.log` — кожен блок: скільки відкинув
    би і чиє рішення. У тіні `Dropped:N` означає «відкинув би N».
- Режим видно в `metric sokol_enforce_mode` і в аудиті (`ENFORCE_MODE|Mode:observe`).
- Перехід до відкидання: `--enforce drop` і рестарт. Рішення, що діють, зберігаються.

## 10. Чи випливає рішення з того, що записано

```shell
sudo sokol-orchestrator --replay /var/lib/sokol/audit.log
```

Перевіряє ланцюжок і проганяє рішення детекторів тим самим кодом (ADR-0016):
- `N reproduced` — рішення відтворено;
- `MISMATCH` — рішення не випливає з записаних входів (з обома значеннями);
- `INSUFFICIENT` — бракує контексту, з причиною. Найчастіше це інша збірка або запуск,
  що відновив стан із файлу.

Запускайте той самий бінарник, що ухвалював рішення.

## 11. Пакет для підтримки

```shell
sudo CONTROL=/run/sokol/control.sock PEERS=/etc/sokol/peers.json scripts/support-bundle.sh
```

Створює `sokol-support-<час>.tar.gz` (`0600`). Усередині:
- система, версія й хеш бінарника;
- стан systemd і журнал;
- метрики, бани, перевірка аудиту;
- прив'язки XDP, стан BPF;
- піри (лише ID й тип ключа).

Ключа вузла й сирих файлів стану та аудиту там **немає**; smoke перевіряє, що байтів ключа
немає в жодному файлі пакета.

## Репетиція

```shell
sudo scripts/runbook-rehearsal.sh <тека зі збіркою> <тека з іншою збіркою>
```

Проганяє цей документ на чистому хості з systemd: команди — як написано вище, трафік — через
veth до мережевого простору імен (бан не відріже оператора). Друга збірка грає оновлення.
Кожне місце, де документ і програма розходяться, друкується як `RUNBOOK DEVIATION`.

Перевіряє: §1–§3 (зокрема кожен рядок таблиці перевірок, крім дашборда), §5.1, §5.4, §7, §8 і
пакет для підтримки. Не перевіряє: збірку з джерел, меш і ротацію ключів (§5.5, §6 — потрібні
інші вузли), адаптери детекторів (§5.6).
