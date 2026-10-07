# Copyright and licensing

Copyright © 2026 Ольга Скороход (ValkyrieSentinel) and the Sokol-Core contributors.

| Path | License | SPDX |
|---|---|---|
| everything not listed below (the node, adapters, scripts, deployment, documentation) | GNU Affero General Public License, version 3 only — [`LICENSE`](LICENSE) | `AGPL-3.0-only` |
| [`ebpf/`](ebpf/) — the XDP program | GNU General Public License, version 2 or later — [`ebpf/LICENSE`](ebpf/LICENSE) | `GPL-2.0-or-later` |
| [`common/`](common/) — types shared by the XDP program and the node | GNU General Public License, version 2 or later — [`common/LICENSE`](common/LICENSE) | `GPL-2.0-or-later` |

**Why two licenses.** The kernel loads an XDP program only under a GPL-compatible license
declaration, and the program is built together with `common`. GPL-2.0-or-later can be combined
with the AGPL-3.0 node, which embeds the compiled program.

**What the AGPL asks.** Anyone may use, study, change and share Sokol-Core. Whoever runs a
changed version for others over a network must offer them its source under the same license
(section 13). There is no warranty (sections 15–16).

**Other terms.** The copyright holder can grant Sokol-Core under other terms, for example for
use in a closed product. Contact: ValkyrieSentinel on GitHub
(<https://github.com/ValkyrieSentinel>).

**Contributions** are accepted under [`CLA.md`](CLA.md).

**Earlier versions.** Commits before this license was adopted carried an all-rights-reserved
notice. With this change the copyright holder licenses them under the terms above as well.
