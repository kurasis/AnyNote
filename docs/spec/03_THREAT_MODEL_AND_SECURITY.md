# Threat Model and Security Requirements

## 1. Assets and adversaries

Assets include readable content, account identity, device private keys, recovery secrets, group keys, authorization history, local drafts, session credentials, release-signing credentials, and backup integrity. Adversaries include a remote unauthenticated attacker, another account, a removed participant, a stolen-device holder, a compromised API/storage operator, a malicious attachment sender, and a dependency or build compromise.

Trust the currently installed approved client, cryptographic libraries, operating system while not compromised, the user's out-of-band identity verification, and correctly retained recovery material. Trusting an account means accepting that its owner can copy all readable content and can authorize its own devices.

## 2. Security claims

| Scenario | Required result / boundary |
| --- | --- |
| MariaDB or blob-store snapshot stolen | No content plaintext or usable content private keys; metadata remains visible |
| Laravel APP_KEY or server session keys stolen | May compromise server control/authentication; must not directly decrypt content |
| API modifies ciphertext or substitutes chunks | Clients reject through AEAD/signature/context validation |
| API adds a fake member/device | Clients reject absent a valid trusted authorization chain |
| API hides data or returns an old valid history | Availability not guaranteed; detect rollback against retained checkpoints where possible |
| API forks views between isolated clients | Not universally prevented in v1; checkpoint comparison can expose it later |
| Removed member retains cached keys/content | Previously readable data remains readable; new epochs exclude them |
| Malware on an unlocked endpoint | Content protection cannot be guaranteed |
| PWA static origin/build compromised | Malicious code may exfiltrate during unlock; E2EE does not solve this |
| Admin deletes account/content storage | Can destroy availability; independent backups mitigate |

## 3. Required controls

SEC-001: Encrypt content on the device before any network request or persistent plaintext log.

SEC-002: Authenticate and authorize every object, revision, upload, chunk, key envelope, and export request. UUIDs do not constitute authorization. Prevent cross-group attachment references and cross-account enrollment completion.

SEC-003: Use TLS with valid certificate verification, modern supported configuration, and HSTS after deployment validation. Never ship certificate-validation bypasses or permissive development CORS in production.

SEC-004: Validate WebAuthn challenge, origin, RP ID, user verification, challenge lifetime, and single use. Do not assume a signature counter alone reliably detects cloning of synchronized passkeys.

SEC-005: State-changing PWA requests use session cookies and CSRF protection. Keep session identifiers out of localStorage. Rotate sessions after authentication/security changes; provide server-side revocation.

SEC-006: Treat all decrypted content and imported data as untrusted. Disable raw HTML in Markdown; sanitize link schemes; prevent DOM injection, remote image tracking, embedded scripts, and template execution.

SEC-007: Enforce restrictive CSP and minimal native capabilities. Do not disable CSP to accommodate a dependency. If WASM needs a policy exception, select the narrow supported directive and record the reason; do not allow arbitrary eval or remote scripts.

SEC-008: Bound body lengths, envelope sizes, JSON nesting, chunk counts, memory allocation, KDF parameters, concurrent jobs, and retry rates before expensive work. A malicious server response can also be a client DoS input.

SEC-009: Keep logs/metrics content-free. Redact cookies, authorization headers, recovery/enrollment secrets, invitation tokens, PRF results, plaintext query terms, file names, and note bodies. Disable request-body capture in APM and crash reporting. Security event logs still contain sensitive metadata and need short retention/access control.

SEC-010: Isolate release credentials from the runtime server. Windows update signatures and OS code signing are distinct controls. PWA deploy permissions are a high-value secret boundary.

SEC-011: Store only ciphertext persistently on the client except explicitly initiated plaintext export. Search indexes and outbox contents need encryption, not only encrypted original notes. Document unavoidable OS/browser memory and export remnants; do not promise perfect JavaScript memory zeroization or SSD secure erasure.

SEC-012: Prevent CSRF, IDOR, SQL injection, mass assignment, path traversal, symlink escapes, response splitting, SSRF, open redirects, archive extraction traversal, and upload overwrite. Never build blob paths from filenames or unvalidated routes.

SEC-013: Rate-limit by account/session/device as well as IP; enforce global upload concurrency and reserved-space ceilings. Do not rely solely on IP limits behind shared networks.

SEC-014: Closed registration, single-use invitations, recent-auth checks for credential changes/recovery/security exports, visible device enrollment notifications, and independent recovery credentials.

SEC-015: Fail closed on unknown protocol, invalid identity, missing authorized recipient envelopes, signature failure, and decrypted-schema mismatch. Preserve recoverable ciphertext for diagnosis without rendering unverified content.

## 4. Browser delivery risks

Deploy the static PWA independently from PHP where feasible. Pin dependencies, bundle assets, omit third-party scripts/fonts/analytics, and audit service-worker cache rules. These mitigate but cannot cryptographically prevent a malicious application origin from changing the verifier itself. SRI or an in-page signature check is not an independent trust anchor when the attacker can replace the HTML/verifier [SRC-04, SRC-05].

Native Windows bundles the UI and verifies signed updates. This reduces dependence on live API content but does not make compromised native dependencies or an authorized malicious update harmless. Never load remote HTML into the privileged main window.

## 5. Group integrity and freshness

AEAD proves possession of a symmetric key, not which participant authored a record. Device signatures and validated roles are required for authorship and reader/write separation. Every signed event binds group, object, revision, account/device, membership version, key epoch, and predecessor as applicable.

Store per-account roster and per-group policy/event checkpoints locally. Exchange checkpoints through verified device enrollment and account sync. Detect sequence regression and incompatible parents. Do not claim a server-generated monotonically increasing integer proves honesty; it is only a synchronization cursor.

Removal and rekey cannot protect writes created by a device that has not learned about revocation and is being actively isolated by a malicious server. Require freshness synchronization before committing shared mutations and document that v1 does not provide a globally consistent independent transparency service.

## 6. Privacy ledger

The service may observe account handles or authentication contact addresses, public keys, account/group/device IDs, membership graph, revision relationships, ciphertext size, exact plaintext file length under the fixed-size v1 chunk framing, activity times, IP addresses, and notification endpoints. Titles, filenames, text, and tags remain encrypted. Exact file size is intentionally visible: without padding, subtracting fixed AEAD tags reveals it. No full content hash or plaintext filename is sent for deduplication. Minimize metadata retention; encrypted disks add defense in depth but do not turn operational metadata into E2EE.

## 7. Verification and independent review

Map controls to OWASP ASVS Level 2 as a baseline, recording the edition used during implementation, with stronger review of crypto, authentication, storage, and update paths. Include dependency/secret scanning, protocol fuzzing, adversarial multi-account tests, and an independent cryptographic/security review before a production security claim. Do not assert ASVS certification from a checklist.

The high-risk review must specifically cover QR trust bootstrapping, account recovery authority, stale device rosters, offline revocation, signed role enforcement, file nonce handling, mobile plaintext export, and release-delivery compromise. Test only owned/synthetic environments unless additional authorization is provided.

## 8. Additional review controls

SEC-016: Bind enrolled sessions to a verified device using a fresh device-signature challenge covering session/account/service. A submitted device_id is not proof of possession. Re-login cannot silently reactivate a revoked device.

SEC-017: Bound metadata object counts, staged transitions, lookup requests, security-history growth, and per-actor mutation rates as well as bytes. Security headroom is reserved capacity, not an infinite availability guarantee on a full physical disk.

SEC-018: Treat push subscription URLs as SSRF inputs. Use a maintained allowlist of supported HTTPS push-service origins, validate resolved addresses against private/link-local/loopback ranges, and forbid unsafe redirects. A disabled unsupported provider is preferable to unrestricted server HTTP posting.

SEC-019: Device compromise revoke includes delegated descendants and pending approvals. Preserve historical evidence while preventing future authorization. Protect saved-but-unsynced content from automatic local erasure after a revoke notice.
