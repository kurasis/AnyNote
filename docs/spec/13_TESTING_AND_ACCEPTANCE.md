# Testing and Release Acceptance

## 1. Evidence policy

Every mandatory test has status PASS, FAIL, BLOCKED, or NOT RUN, plus environment, date, command/procedure, result artifact, and limitation. A code review is not runtime evidence. An emulator is not a physical iPhone. A Windows build produced on Linux is not a Windows WebView2 runtime test. Synthetic sample keys may be committed; real keys and production data may not.

Use meaningful tests against risks and contracts, not tests that repeat implementation details. Run a targeted suite per phase and broader suites at integration gates. Keep fixtures reproducible; fuzzing seeds and failing inputs are retained without secrets.

## 2. Platform matrix

| Environment | Required coverage |
| --- | --- |
| Linux CI | Laravel/MariaDB integration, contract, public verification, backend concurrency, backup consistency |
| Windows 11 + WebView2 | Native key storage, Hello behavior, IPC, transfers, lock/suspend, updater/install |
| Chromium browser | UI/contract and PWA baseline automation |
| Automated WebKit | Rendering/protocol smoke coverage only; not final iPhone evidence |
| At least two real supported iPhones | One lower-memory/older supported device and one current device; PWA lifecycle, storage, passkeys, PRF where offered, 1 GB import/export |
| Clean-client recovery environment | Account/device recovery from offline kit and restored ciphertext without old local state |

If only one physical model is available, record narrower tested support; do not claim a broader validated range. The owner must accept any reduced release scope.

## 3. Functional and collaboration acceptance

| ID | Test | Required outcome |
| --- | --- | --- |
| F01 | Create account from valid/expired/replayed invitation | One valid account; other attempts fail safely |
| F02 | Account A/B private groups | Neither sees the other's private content/key envelopes |
| F03 | Shared group owner/editor/reader | Every operation matches role matrix at API and client verification |
| F04 | Reader crafts a valid AEAD payload using known group key | Rejected as a content write without authorized writer signature/state |
| F05 | Invite with retained history/trash | Explicit consent and all retained required keys; no half-active membership |
| F06 | Shared copy from private group | New IDs/keys; selected current content only unless history explicitly selected |
| F07 | New same-account device | Receives authorized groups without copying another device private key |
| F08 | Ownership transfer | Both consent; never zero/two owners |
| F09 | Archive/unarchive | Content read-only while archived; maintenance/recovery behavior documented |
| F10 | Account delete owning shared groups | Transfer/delete resolution required; no administrator decryption shortcut |

## 4. Cryptography and identity acceptance

| ID | Test | Required outcome |
| --- | --- | --- |
| C01 | Native encrypt -> browser decrypt and reverse | Exact shared fixtures pass |
| C02 | Rust/TS/PHP signature/JCS verification | Identical byte interpretation; duplicate-key/nonfinite/invalid-Unicode inputs fail |
| C03 | Wrong key, tag, nonce, AAD, group, revision | Deterministic integrity failure, no plaintext display |
| C04 | Sealed envelope from unauthorized sender | Rejected despite decryptable envelope |
| C05 | Server substitutes root/device/recipient key | Rejected without verified authorization/OOB trust |
| C06 | Enrollment replay/reflection/cross-account relay | No unauthorized certificate or key release |
| C07 | Recovery derivation contexts | Root/recovery/local-wrap purposes are separated; device identity keys are independently random; version fixtures fixed |
| C08 | Invalid/oversized KDF parameters | Reject before excessive allocation/work |
| C09 | Historical revision from now-removed author | Old valid history verifies; new unauthorized writes fail |
| C10 | Nonce reuse/source-change retry | Reuse prohibited; changed input starts new version/key |
| C11 | Removed device authorizes a new device using stale roster | Rejected when revocation is known; stale-server boundary documented |
| C12 | Key rotation during concurrent writes | One current epoch; stale writes reconciled, no old-recipient publication |
| C13 | Recovery reset | Old sessions/devices invalid; current client accepts valid root-signed generation only |
| C14 | Known rollback/fork below local checkpoint | Warning/quarantine; no silent trust downgrade |
| C15 | Fresh client with no independent checkpoint | Limitation documented; no claim of universal rollback detection |
| C16 | Removed writer signs new content with a backdated timestamp and retired policy | No acceptance as trusted historical content without valid checkpoint/ancestry evidence |

## 5. Sync and durability acceptance

| ID | Test | Required outcome |
| --- | --- | --- |
| S01 | Kill app after local-save acknowledgement | Encrypted note/outbox survives ordinary restart |
| S02 | Lose server response and retry mutation | Exactly one logical result |
| S03 | Reuse idempotency key with changed body | Conflict, no side effect |
| S04 | Two devices edit same base offline | Both edits preserved, explicit resolution |
| S05 | Concurrent delete/edit/restore | No silent resurrection or discarded edit |
| S06 | Cursor expires/full resync while outbox exists | Stable snapshot + subsequent delta, outbox retained |
| S07 | Member removed/editor downgraded while offline | Unsent work preserved privately; no unauthorized commit |
| S08 | Partial/corrupt delta page | No silent cursor advancement past lost work |
| S09 | Reconnect after device revoke | No new keys/data; best-effort cache action does not imply remote erasure |
| S10 | Cache cleanup | No server delete and no loss of unsynced work |
| S11 | PWA service-worker/local schema update | Pending work preserved or safely recoverable |
| S12 | Server restored behind client checkpoint | Explicit restore generation and rollback reconciliation |

## 6. File acceptance

Use byte sizes 0, 1, chunk_size-1, chunk_size, chunk_size+1, 1,000,000,000, and 1,000,000,001. Use incompressible synthetic content, Unicode/reserved filenames, malformed documents, and modified sources. Measure incremental memory, not just a successful request.

| ID | Test | Required outcome |
| --- | --- | --- |
| U01 | Maximum and oversize files | Maximum succeeds on supported flows; oversize rejected before expensive transfer |
| U02 | 120-part maximum file and short final part | Exact chunk accounting, manifest, tag overhead |
| U03 | Missing/reordered/duplicated/trailing/substituted part | Reject incomplete/corrupt result |
| U04 | Retry same/different bytes at same upload index | Same bytes idempotent; different bytes rejected |
| U05 | Network cut during part/commit | Resume without duplicate quota or visible partial file |
| U06 | Source changes or source reselected after restart | Strong identity checks or safe new version/key |
| U07 | Role removal/rekey during upload | Commit blocked; private draft/staging preserved for safe resolution |
| U08 | Concurrent reservations near 100 GB | No oversubscription; stable counters after cancel/expiry |
| U09 | Janitor races with commit | No committed chunk loss |
| U10 | Windows 1 GB upload/download/export | Correct bytes, bounded memory, cancel/resume |
| U11 | Real iPhone 1 GB upload/download/save to Files | Correct final file and measured bounded pipeline; not a desktop simulation |
| U12 | iPhone lock/background/force-close/low space | Honest paused/needs-source state, no false completion |
| U13 | 72-hour expired upload | Correct error, reservation reclaimed, no ID reuse ambiguity |
| U14 | Cross-group/cross-user chunk ID or internal URL | Authorization failure, no data leak |
| U15 | Unsafe file names/archive/PDF/image | No path escape, script execution, automatic launch, or unbounded decode |
| U16 | Plaintext inspection of server stores | No filename/body/content/keys; ciphertext-only upload buffers |
| U17 | User content quota full during device revoke/recovery/rekey | Security transition succeeds within restricted maintenance reserve; ordinary uploads still fail |

## 7. Client and application security

X01: Stored/reflected/DOM XSS payloads in Markdown, titles, tags, filenames, links, and imported notes. No code execution or key/API abuse.

X02: IPC invocation from preview/foreign origin with forged arguments. No filesystem, shell, key, or network privilege escalation.

X03: Lock while async decrypt/export is pending. No stale unlock capability continues unauthorized decryption.

X04: Forged WebAuthn origin/RP/challenge, replayed challenge, expired invitation, and recovery brute-force. Fail safely with bounded costs.

X05: CSRF, permissive CORS, cookie flag, redirect URI, PKCE/state, refresh reuse, and session revoke tests. Unauthorized sessions cannot bypass device trust.

X06: Database/filesystem/log/APM/crash artifact inspection after realistic use. No unexpected plaintext, secrets, PRF outputs, or recovery kit.

X07: PWA offline caches/service-worker fetch rules. No plaintext export/authentication response cached by broad rules.

X08: Update tampering/downgrade/untrusted signer. Rejected; existing encrypted state preserved.

X09: Search after lock/revoke/delete. No stale readable results; persistent index encrypted.

X10: Local OS wrapper/Hello test. Demonstrate actual key gating or clearly document lower protection.

## 8. Operations acceptance

O01: Clean installation from documented steps, not developer machine residue.

O02: Backup while writes/cleanup occur, restore to clean host, reference reconciliation, clean-device decryption and 1 GB export.

O03: Physical disk exhaustion, database outage, failed fsync/object store, worker restart. No false success or corrupt quota.

O04: Expired session/invite/upload and key-envelope cleanup. No lost committed references.

O05: Incident drill for API/PWA delivery compromise and lost recovery secret. No admin decryption escape hatch.

O06: Capacity fixture with 10 accounts/50 devices, 100,000 retained revisions, 100 GB logical ciphertext inventory where feasible. Report latency, memory, disk usage, and limits; avoid filling a production disk for testing.

## 9. Performance targets

On the declared reference hardware/network: local note save acknowledgement p95 <=250 ms after explicit save for a typical <=100 KB note; warm local search p95 <=500 ms over 10,000 ordinary notes; visible-client sync convergence typically <=10 seconds on healthy network with 5-second polling; first group catalog view <=2 seconds with local cache. Larger payloads and cold bootstrap have separate measurements.

Do not label these targets measured until evidence exists. Transfer throughput is reported relative to network/disk baseline; do not promise a fixed MB/s across iPhones. UI must remain interactive under transfer and search load.

## 10. Release gates

G0: Scope/version/dependency matrix agreed and synthetic test environment reproducible.

G1: P01 physical-platform feasibility, especially 1 GB iOS export, recorded. If blocked, production scope is not silently approved.

G2: Crypto protocol frozen, interoperability fixtures pass, qualified independent review findings resolved or explicitly accepted with a narrowed claim.

G3: Functional, authorization, revocation, conflict, and file suites pass with no critical/high unresolved exploitable issue.

G4: Signed Windows release/update verification, hardened static PWA, real-device matrix, and local storage migration checks pass.

G5: Clean-host backup restore and content recovery pass; operators receive runbooks and measured RPO/RTO.

G6: Final acceptance report lists all remaining limitations. No plaintext server fallback, mock crypto, test-auth bypass, ignored integrity exception, or fabricated result remains enabled.

## 11. Specification-review regression cases

These are required implementation tests derived from the document review, not results already obtained. Use hostile clients/relay fixtures and deterministic transaction scheduling where relevant.

| ID | Scenario | Required outcome |
| --- | --- | --- |
| R01 | Fresh recipient with no uploader cache downloads a file | Device/recovery key -> epoch -> manifest DEK -> file-data DEK -> exact original bytes; server never obtains these keys |
| R02 | Recovery from a completely new untrusted device | Separate login then root challenge/reset activates new device before recovery-envelope access; removed groups stay denied |
| R03 | Transaction A delays after event allocation while B tries to commit; concurrent reader polls | B cannot advertise a later sequence before A commits/rolls back; no event skipped |
| R04 | Actual app/API sibling origins, hostile sibling, preflight and session rotation | Host-only cookie works, exact CORS and synchronizer CSRF reject attacker, API cannot supply app scripts |
| R05 | Logged-in attacker supplies a victim device ID | No trusted-device session without fresh possession proof bound to that session |
| R06 | Approval expires or races with revocation before enrollment confirm | No active device, session upgrade or keys; activation is one atomic validated transition |
| R07 | Compromised device enrolled two descendants before revoke | Descendants, sessions and pending approvals are also revoked; independent devices remain |
| R08 | Reader loses a device while owner offline | Reader may rotate exact existing recipient set, cannot write/change roles; history remains protected until required writer closure |
| R09 | Commit response lost then epoch changes or conflict occurs | Old receipt checked first; same operation bytes stay immutable; new attempt cannot duplicate a successful old publication |
| R10 | Snapshot pages overlap concurrent edits/deletes, invitation and GC | Consistent watermark and pinned inventory; all later changes obtained; no deletion inferred from incomplete page; revoked access denied |
| R11 | Crash between file commit and entry publication | Quota counted once; recoverable unattached file visible; retry attaches once or explicit cleanup |
| R12 | More than three file versions referenced by retained note history | Referenced bytes survive; UI explains pins; collection only after final strong reference expires |
| R13 | Maximum-size file plus framing; two simultaneous uploads; epoch changes after partial upload | Reservation/cache arithmetic works; epoch change restarts with new keys/AAD; ordinary network resume reuses identical ciphertext |
| R14 | Removed writer submits newly signed backdated revisions; reader signs a history closure | Retired-policy data lacks required witnessed/inventory proof and is quarantined; reader cannot certify writer history |
| R15 | Many empty objects, oversized nested JSON, repeated transitions/snapshots | Count/depth/time/rate bounds apply independently of byte quota; normal data and maintenance retain bounded availability |
| R16 | Local DB rolled back then same record edited; adversarial KDF parameters | Fresh random local nonce, no replayed counter; excessive KDF rejected before allocation, correct cross-binding vectors |
| R17 | Valid initial age chunks but corrupt/truncated footer or duplicate tar paths | No trusted live import before complete validation; only encrypted staging; no unsafe extraction or secret temp files |
| R18 | Native callback IP/path/issuer/PKCE changes or code reused/expired | Handoff rejected; tokens never in callback URL; no embedded secret or public listener |
| R19 | Signed ciphertext transplanted to another thread/attachment inventory; mutated key-wrap bytes | Context/signature/AAD checks reject; IDs cannot substitute for signed digests |
| R20 | Two PWA windows, leader crash, old worker reply after lock, passkey/file sheet hides app | Fenced single publication, no stale decryption, recoverable flow, no unlock loop or plaintext cache |
| R21 | Invite target changes identity/declines; one grant missing/wrong | No premature membership; structural completeness checked, bad unwrap enters explicit repair state |
| R22 | Backup predates member/device/passkey revocation | Restored credentials disabled and groups quarantined until reconciled; no silent rollback of security policy |
| R23 | User quota full, reserve nearly full, or physical storage fails mid-revoke | Bounded reserve used only for maintenance; no false durable success; actionable fail-closed recovery |
| R24 | Push endpoint points at loopback/link-local/internal host or redirects/rebinds DNS | No unsafe outbound request; supported provider allowlist, address revalidation and redirect restrictions |

For R03/R10/R11/R22 record the exact failure injection and state before/after recovery. A unit test that repeats the same implementation logic is insufficient evidence for transaction ordering, physical durability or restore authorization.
