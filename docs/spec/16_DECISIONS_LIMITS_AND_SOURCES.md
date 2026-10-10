# Decision Register, Limits, and Primary Sources

Prepared/checked: 2026-10-10. Recheck time-sensitive versions and platform compatibility when implementation begins. Source documentation supports component behavior; it does not certify this application's design.

## 1. Accepted product decisions

| ID | Decision |
| --- | --- |
| D01 | Small invite-only service for trusted people, independent accounts |
| D02 | Private and shared groups included in v1; threads inherit group permissions |
| D03 | Owner/editor/reader roles; one group owner; no administrator master decryption key |
| D04 | Windows uses WebView2 via Tauri 2 + Rust; shared React/TypeScript UI |
| D05 | iPhone uses an installed PWA, with explicit browser delivery/background/storage limitations |
| D06 | Server stack is Laravel + MariaDB + Nginx + PHP-FPM |
| D07 | Notes/metadata in MariaDB as ciphertext; file bytes in private blob storage |
| D08 | QR trusted-device enrollment and offline account-specific recovery |
| D09 | Login and decryption are separate; PRF is optional after actual capability tests |
| D10 | Group epochs and immutable per-revision/file DEKs; signed authorization and authorship |
| D11 | Full retained history is shared with new group members, including retained trash; explicit warning |
| D12 | Private-to-shared action creates selected encrypted copies, not an implicit audience toggle |
| D13 | Local search; no server plaintext search, preview generation, OCR, or AI |
| D14 | Offline outbox, conflict preservation, chunk resume, and tested backup recovery |
| D15 | Global 100 GB allocation is for all accounts together, shared files counted once |
| D16 | Revocation protects future epochs; previously readable copies cannot be revoked |

## 2. Authoritative numerical defaults

These values are defaults unless explicitly identified as fixed agreed limits. Configuration changes must remain inside tested protocol/resource bounds.

| Setting | Value | Classification |
| --- | --- | --- |
| Maximum original file | 1,000,000,000 bytes | Agreed v1 limit |
| Global committed content quota | 100,000,000,000 bytes | Agreed initial service quota |
| Size units | GB = 10^9 bytes; GiB = 2^30 bytes; MiB = 2^20 bytes | Fixed terminology |
| Default chunk plaintext length | 8,388,608 bytes | Versioned format default |
| Maximum-file chunks | 120; final plaintext part 1,755,648 bytes | Derived from limits |
| Windows chunk concurrency | Up to 4 per transfer | Tune within memory cap |
| PWA chunk concurrency | 1–2 per transfer | Tune after real-device tests |
| Simultaneous upload sessions | 2 per account; 8 service-wide | Default, bounded |
| Pending reservations | <=2 GiB/account; <=5 GiB/global; also global/free-space check | Default resource protection |
| Security-maintenance reserve | 100 MiB beyond content quota, restricted to validated key/recovery transitions | Operational default; not general file capacity |
| Upload inactivity expiry | 72 hours | Default |
| Account invite expiry | 48 hours | Default |
| Pairing session expiry | 10 minutes | Default |
| Active devices/account | 5 | Configurable initial cap |
| Auto-lock inactivity | 5 minutes | User-configurable secure default |
| Native access credential | 15 minutes | Default |
| Maximum session/refresh lifetime | 30 days | Default; shorter operator policy allowed |
| Recent-auth window | 5 minutes | Default for sensitive operations |
| PWA server session idle timeout | 12 hours | Default; absolute lifetime <=30 days |
| Trash retention | 30 days | Default |
| Retained file versions | Soft target of 3 total including current; strong references may retain more | Default |
| Note history | All 30 days, daily to 90 days, monthly afterward; current/conflict/pinned/required ancestry retained | Compaction only after verified implementation |
| Automatic downloaded-file cache | iPhone 1 GiB; Windows 5 GiB | Soft app caps; physical quota overrides |
| Sync page | 200 default; 1,000 maximum | Resource bound |
| Foreground sync polling | 5 seconds with jitter; 15–60 seconds backoff | Default |
| Mutation receipt retention | At least 30 days | Default; immutable IDs still protect later retries |
| Global sync-log retention | At least 90 days | Default; old cursors force full resync |
| Compact tombstones/security ancestry | Indefinite in v1 | Small metadata; future compaction requires protocol design |
| Diagnostic/security logs | 30 days | Default; restricted incident exception |
| Backup retention | 14 daily + 8 weekly recovery points | Initial policy |
| RPO / RTO targets | <=24 hours / <=8 hours | Must be measured by restore drills |
| Storage warning thresholds | 80%, 90%, 95% | Default |
| Typical content-size limit per note revision | 2 MiB serialized plaintext | v1 resource bound; attachments for larger text |
| Encrypted JSON/control body ceiling | 4 MiB unless endpoint-specific schema permits less | Resource bound; binary chunk routes separate |
| Binary chunk request ceiling | Chunk size + AEAD framing, capped at 9 MiB for default profile | Route-specific resource bound |
| Title/tag bounds | Title 256 Unicode scalar values; tag 64; max 50 tags/object | Decrypted-schema constraints |
| Attachments/entry | 100 references | UI/schema resource bound |
| Group members | 20 by default | Above initial 2–10 account sizing; configurable after tests |
| Preview text | First 1 MiB by default | Preview cap, original retained |
| Native one-use authorization code | 60 seconds | Bound to client, exact callback and PKCE |
| Resync snapshot lease | 30 minutes | Scoped materialized inventory; reauthorize every page |
| Export snapshot lease | Renewable within 24-hour total lifetime; one/account | Restart cleanly after expiry; no indefinite pins |
| Committed unattached-file recovery | 30 days | Quota counted; live references prevent collection |
| Public signed control header | 64 KiB | Endpoint schemas may require less |
| Staged inventory page | <=500 items and <=1 MiB | Both limits apply; digest/count committed |
| JSON nesting | <=32 levels | Bound before deep parsing |
| Groups/account | 200 active plus retained trash | Configurable abuse-protection cap |
| Threads/group | 10,000 current plus retained trash | Configurable abuse-protection cap |
| Content object count/account | 100,000 current plus retained trash | Separate from byte quota; no silent deletion |
| Retained revision hard service ceiling | 1,000,000 | Capacity alarm and reject new content before exhaustion |
| Pending security transitions | 1/group | Serialized by expected heads |
| Minimum free data-volume space | max(10 GiB, 10% of volume) | Stop new reservations below threshold |
| Local KDF | Argon2id v1.3, 64–256 MiB, libsodium opslimit 3–10 | Calibrated; one job at a time; file 04 |

For server validation, encrypted plaintext fields cannot be inspected; clients enforce decrypted schema bounds, while the server enforces envelope/ciphertext limits and signed structural constraints. Malicious authorized clients may encrypt malformed content; receivers reject it safely. Titles/tags must not be sent in plaintext just to enforce a limit.

## 3. Engineering gates, not hidden unresolved product choices

| Gate | Resolution required | Owner phase |
| --- | --- | --- |
| Exact maintained dependency versions | Record current release/support/compatibility; pin lockfiles | P00 |
| Real iPhone 1 GB export and resume | Physical-device measurements and supported pipeline | P01/P15 |
| Windows key protection/Hello | Demonstrate actual key gating; document DPAPI/user-context limits | P01/P07 |
| PRF providers/credentials | Actual feature detection and matrix; strong fallback | P01/P15 |
| Pairing transcript and wire encodings | Select reviewed construction; freeze fields/vectors | P02 |
| Native auth-code/refresh implementation | Maintained mechanism, state/PKCE, replay/reuse tests | P02/P06 |
| Root/roster/group protocol composition | Qualified independent review and remediation | P02/P17 |
| Portable export encoding | Self-describing, streaming, recovery/import verified | P13 |
| Physical server capacity and recovery targets | Measured load and clean-host restore | P16 |

No developer may resolve a failed gate by silently removing E2EE, sending plaintext to the server, hiding a platform limitation, or changing the agreed user scope.

## 4. Primary-source register

### SRC-01 — Laravel support and release policy

[Laravel release notes](https://laravel.com/docs/13.x/releases). Checked reference: Laravel 13 requires PHP 8.3 or newer within its supported matrix. Pin an actively maintained compatible version at implementation time; do not enable optional AI services merely because the framework includes them.

### SRC-02 — Tauri security and permissions

[Tauri security](https://v2.tauri.app/security/) and [capabilities](https://v2.tauri.app/security/capabilities/). Used for native/frontend trust boundaries and least-privilege capability design.

### SRC-03 — WebView2 security

[Microsoft: Develop secure WebView2 apps](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security). Used for origin validation, constrained native bridges, navigation restrictions, and standard-user execution.

### SRC-04 — Browser cryptography threat boundaries

[W3C Web Cryptography API](https://www.w3.org/TR/webcrypto/). Used for client-side cryptography concepts and limitations concerning script injection/key storage. Browser cryptography does not authenticate the application delivery channel independently.

### SRC-05 — CSP

[W3C Content Security Policy](https://www.w3.org/TR/CSP/). Used for restricting resource/script execution; CSP is defense in depth, not protection from a malicious origin that supplies the policy itself.

### SRC-06 — Password-derived keys

[libsodium password hashing](https://doc.libsodium.org/password_hashing/default_phf). Used for Argon2id, salt/parameter persistence, and device-specific resource calibration. The application's starting parameters require measurements.

### SRC-07 — Authenticated encryption and file streams

[libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) and [secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream). Used for primitive capabilities and the distinction between ordered streams and independent chunk access.

### SRC-08 — Recipient envelopes

[libsodium sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes). Sealed-box recipient confidentiality does not authenticate the sender; the application requires signed distribution authorization.

### SRC-09 — Canonicalization and derivation

[RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) and [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869). Used for interoperable signed bytes and purpose-separated derivation. JCS is an informational RFC; specify the selected profile precisely.

### SRC-10 — WebAuthn and PRF

[W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/). Used for public-key authentication and PRF extension behavior. PRF secret output intended for local encryption must be excluded from server-bound credential serialization.

### SRC-11 — Laravel SPA sessions

[Laravel Sanctum](https://laravel.com/docs/13.x/sanctum) and [Laravel encryption](https://laravel.com/docs/13.x/encryption). Used to distinguish cookie/CSRF SPA authentication and server APP_KEY encryption from content E2EE.

### SRC-12 — WebKit storage

[WebKit storage policy](https://webkit.org/blog/14403/updates-to-storage-policy/). Used for quotas, persistence requests, eviction, and installed-app storage considerations. Quota estimates are not guaranteed free space.

### SRC-13 — OPFS

[WebKit File System API with OPFS](https://webkit.org/blog/12257/the-file-system-access-api-with-origin-private-file-system/). OPFS is origin-private storage, not proof that a large file can be exported to iOS Files in the desired workflow.

### SRC-14 — iOS push

[WebKit Web Push on iOS/iPadOS](https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/) and [Meet Web Push](https://webkit.org/blog/12945/meet-web-push/). Used for installed-PWA notification support and the boundary against indefinite silent background execution.

### SRC-15 — Windows update verification

[Tauri updater](https://v2.tauri.app/plugin/updater/). Used for application update signatures, which are separate from OS installer code signing.

### SRC-16 — Nginx internal file delivery

[Nginx core module: internal](https://nginx.org/en/docs/http/ngx_http_core_module.html#internal). Used for private internal delivery after application authorization; configuration must be tested against bypass and path attacks.

### SRC-17 — Application-security references

[OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html), [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), and [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html). Used as baseline security engineering references; encrypted uploads need client-side content-safety controls rather than plaintext server scanning.

### SRC-18 — Database encryption distinction

[MariaDB data-at-rest encryption](https://mariadb.com/docs/server/security/securing-mariadb/encryption/data-at-rest-encryption/data-at-rest-encryption-overview). Database/disk encryption is an additional operational control and is not a replacement for client-held E2EE keys.

### SRC-19 — Portable export encryption

[age v1 format](https://age-encryption.org/v1) and [official age implementation](https://github.com/FiloSottile/age). Used as an established outer streaming encrypted-file format for portable exports. The application's inner inventory, source identity verification, and import workflow still require their own validation.

### SRC-20 — CSRF and session boundaries

[OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) and [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). Used for synchronizer tokens, credentialed cross-origin requests, host-only cookies, session rotation and origin checks.

### SRC-21 — Native browser authorization

[RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252) and [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700). Used for system-browser authorization, public clients, PKCE, loopback redirects and token/session attack controls. Use a maintained implementation; these documents are not permission to improvise an authorization server.

### SRC-22 — MariaDB allocation and transaction semantics

[MariaDB AUTO_INCREMENT handling in InnoDB](https://mariadb.com/docs/server/server-usage/storage-engines/innodb/auto_increment-handling-in-innodb). AUTO_INCREMENT allocation is not a safe commit-order change-feed watermark. File 07 specifies transactional event counter serialization.

### SRC-23 — Server-side request forgery

[OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html). Used for outbound push endpoint validation, DNS/IP checks and redirect restrictions. No general URL fetcher is part of this product.

## 5. Source and assurance limits

The specification combines the accepted product decisions with engineering recommendations based on primary documentation. It does not claim that the listed libraries form a turnkey audited multi-device group vault. Exact protocol composition, device support, resource consumption, and production deployment must be validated through the roadmap. No benchmark, physical-platform run, penetration test, or cryptographic audit was performed while authoring this package.

## 6. Bounds and upgrade rules

Object, revision and transition caps are independent of encrypted-byte quota. Check them transactionally and return an actionable resource-limit error; never prune required ancestry or current user data to make a counter fit. Release fixtures include near-cap behavior. The 100,000-retained-revision load fixture in file 13 is a measurement baseline, not the 1,000,000 service safety ceiling. Metadata, audit and security-history growth must be monitored even with few file bytes. If safe compaction has not been designed, increase measured capacity or stop new content instead of deleting cryptographic evidence.

Rate limits must separately cover login/recovery, invitations, enrollment, signatures, staged pages, snapshots, uploads and push registration. Exact per-IP/account rates are measured and recorded in P04/P06; a CAPTCHA or IP-only limit cannot replace authentication and bounded work. Security transitions retain a small dedicated rate/budget allowance so ordinary abuse cannot consume every slot.
