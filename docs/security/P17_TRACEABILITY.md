# P17 threat-to-test traceability

The [manifest](p17-traceability.json) binds every R01–R24 to actual authority
and maintained test anchors. `scripts/p17-check.py` rejects stale anchors; this
static check alone never establishes a runtime PASS. Every listed ordinary job
and all30 aggregate jobs must pass on the exact final source.

| Regression | Maintained test / mandatory gate | Bounded claim and remaining assumptions |
| --- | --- | --- |
| R01 | [test-files.mjs](../../packages/protocol/files/test-files.mjs) / `files-linux-http-browser` | Fresh enrolled recipient without uploader journal; inherited1GB gates remain separate from physical iPhone memory/output. |
| R02 | [state.test.mjs](../../packages/protocol/test/state.test.mjs) / `file-contract` | Root reset is separate from login and never restores a removed shared membership. Actual HTTP counterpart also runs in devices-linux-http-browser. |
| R03 | [p04-concurrency.php](../../apps/api/tests/Support/p04-concurrency.php) / `foundation` | Actual two-process counter contention, independent PDO observer and before/blocked/after sequences; not power-loss proof. |
| R04 | [ApiBoundaryTest.php](../../apps/api/tests/Feature/ApiBoundaryTest.php) / `foundation` | Actual TLS origins also run in auth-linux-http-browser and P17. A compromised static origin can replace trusted client code. |
| R05 | [state.test.mjs](../../packages/protocol/test/state.test.mjs) / `file-contract` | Authentication alone never proves device possession. Actual HTTP counterpart also runs in devices-linux-http-browser. |
| R06 | [state.test.mjs](../../packages/protocol/test/state.test.mjs) / `file-contract` | Expiry, current heads and atomic activation also have real lifecycle HTTP tests; physical QR ceremony remains unrun. |
| R07 | [state.test.mjs](../../packages/protocol/test/state.test.mjs) / `file-contract` | Actual HTTP descendant tests also run in devices-linux-http-browser. Revocation cannot erase previously received keys/plaintext. |
| R08 | [group.test.mjs](../../packages/protocol/test/group.test.mjs) / `file-contract` | Exact-recipient mandatory maintenance never confers writer/history-closure authority. Shared real HTTP/browser gates also remain mandatory. |
| R09 | [http.mjs](../../packages/protocol/security/http.mjs) / `adversarial-linux` | Actual TLS response destroyed after response bytes begin;8 identical retries and SQL exactly-once verification. Shared role/epoch-change cases remain separate gates. |
| R10 | [p11-http.mjs](../../packages/protocol/p11-http.mjs) / `sync-linux-http-browser` | Materialized inventory/watermark precedes real concurrent edit and2001 hidden events; file-pin/GC races are additional files/content gates, not a universal server freshness guarantee. |
| R11 | [p12-http.mjs](../../packages/protocol/p12-http.mjs) / `files-linux-http-browser` | Actual commit response loss, lock/reopen, unattached state and quota reconciliation. This particular fixture is not an OS process/power kill; native/installed restart is separate evidence. |
| R12 | [p13-http.mjs](../../packages/protocol/p13-http.mjs) / `content-linux-http-browser` | Retained strong references and explicit pins survive the soft version target; no unbounded retention or SSD secure-erasure guarantee. |
| R13 | [p12-http.mjs](../../packages/protocol/p12-http.mjs) / `files-linux-http-browser` | Actual decimal1GB/120 parts/framing and concurrent commit/GC. Physical100GB inventory remains NOT_RUN; arithmetic is not storage capacity evidence. |
| R14 | [group.test.mjs](../../packages/protocol/test/group.test.mjs) / `file-contract` | History requires independent witnessed ancestry; fresh clients cannot derive universal freshness from the same relay. |
| R15 | [fuzz.mjs](../../packages/protocol/security/fuzz.mjs) / `adversarial-linux` | Finite deterministic mutation and real malformed HTTP admission; byte/count/page/rate bounds do not prove availability against unlimited distributed attackers. |
| R16 | [test-engine.mjs](../../packages/protocol/vault/test-engine.mjs) / `adversarial-linux` | Fresh local random nonces and preallocation KDF bounds; physical memory/time budgets remain open. |
| R17 | [test-portable.mjs](../../packages/protocol/content/test-portable.mjs) / `adversarial-linux` | Full age EOF/footer/inventory/independent pins and encrypted staging are distinct from generic tar framing;10 real operational age negatives also remain mandatory. |
| R18 | [lib.rs](../../packages/auth-native/src/lib.rs) / `auth-windows-native` | Literal loopback/issuer/path/state/PKCE and one-use code; hosted Windows is not physical Hello proof. |
| R19 | [fuzz.mjs](../../packages/protocol/security/fuzz.mjs) / `adversarial-linux` | 512 authenticated envelope mutations; parsing alone never establishes independently pinned trust or role authority. |
| R20 | [test-workflow.mjs](../../packages/protocol/devices/test-workflow.mjs) / `adversarial-linux` | PWA delayed reply/old Worker/lock and installed upgrade gates remain mandatory. Physical iOS sheets/background/force-close matrix remains open. |
| R21 | [group.test.mjs](../../packages/protocol/test/group.test.mjs) / `file-contract` | Exact-target acceptance and complete structural grants never imply successful unwrap; actual three-account HTTP/browser counterparts remain mandatory. |
| R22 | [p16-acceptance.mjs](../../packages/protocol/p16-acceptance.mjs) / `operations-linux-drill` | Actual clean SQL/blob restore, old/new generation, saved cursor and exact encrypted draft/outbox comparison. No automatic current-security reconciliation/unquarantine exists. |
| R23 | [p16-acceptance.mjs](../../packages/protocol/p16-acceptance.mjs) / `operations-linux-drill` | Actual8MiB tmpfs ENOSPC, unavailable object dir, /proc fsync failure, DB outage and worker restart. Production10GiB/10% reserve is unchanged; logical reserves cannot defeat failed storage. |
| R24 | [http.mjs](../../packages/protocol/security/http.mjs) / `adversarial-linux` | Push registration/delivery is unsupported:404 and zero listening-loopback canary requests. Enabled-provider DNS revalidation/redirect handling is NOT_IMPLEMENTED and must precede enabling push. |


R03 records real before/blocked/after sequences for commit and rollback. R10
captures materialized inventory before a concurrent edit and hidden-event scan.
R11 destroys an actual commit response, locks/reopens the encrypted journal and
checks unattached state/quota. R22 compares clean SQL/blob inventory, generations,
saved cursor and exact encrypted draft/outbox bytes. Original hosted reports and
actual source assertions remain separate; models are never relabelled as OS or
power-loss experiments. Independent review, physical devices, memory budgets and
actual100GB inventory remain open. Unsupported push is a closed feature, not
a tested implementation of an enabled outbound provider.
