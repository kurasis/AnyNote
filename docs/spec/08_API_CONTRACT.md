# API Contract and Authorization

## 1. General rules

Base path: /api/v1. HTTPS only in deployed environments. JSON control requests use versioned schemas; chunk requests use application/octet-stream. IDs are opaque. Byte counts and large counters are canonical decimal strings. The implementation must produce an OpenAPI document plus examples and automated contract tests from these requirements.

The routes below define required operations, not permission to skip request/response schemas. Where a single signed mutation endpoint reduces duplication, it may implement several operations if OpenAPI still describes their typed schemas and authorization. Do not expose a generic execute/query endpoint.

All mutating content/security operations have a client operation ID, actor device identity, expected state/version, and a validated signed operation where specified. Auth endpoints and device-untrusted bootstrap flows use their own challenge/session authorization; they cannot be forced into a trusted-device signature before enrollment exists.

## 2. Auth and accounts

| Method / route | Purpose | Authorization |
| --- | --- | --- |
| GET /capabilities | API/protocol ranges, numeric limits, service identity, feature availability | Minimal public data; no secret config |
| POST /auth/passkeys/options | Start registration or assertion | Invitation/active session for registration; bounded public sign-in challenge |
| POST /auth/passkeys/verify | Verify one-time ceremony | Strict WebAuthn verifier, origin/RP/challenge checks |
| POST /auth/logout | Revoke current session | Session + CSRF for cookie clients |
| GET /auth/native/authorize | Start native browser authorization | Registered client, fixed issuer, redirect policy, state/PKCE |
| POST /auth/native/approve | Confirm browser consent and issue single-use code | Authenticated browser session, CSRF, validated authorization request |
| POST /auth/native/token | Redeem code/rotate refresh | Single-use code or valid rotation credential |
| POST /auth/recovery-code | Restore authentication session | One-time code, strong rate limits; not content unlock |
| GET /me | Minimal account/security state | Authenticated account |
| GET/DELETE /me/sessions/{id?} | List or revoke sessions | Same account; recent auth for revoke-all |
| GET/POST/DELETE /me/passkeys/{id?} | Manage authentication credentials | Same account, recent auth; prevent accidental last-method lockout |
| POST /admin/account-invitations | Create invite | Service admin, recent auth |
| POST /accounts/register | Consume invite and attach public identity | Invite, verified auth enrollment, root-signed identity proof |
| POST /admin/accounts/{id}/disable | Disable service access | Service admin; no cryptographic ownership gain |

Implement GET /auth/csrf as file 05's session-bound synchronizer-token bootstrap; do not assume the static origin can read an API-host XSRF cookie. Add POST /auth/device-challenge and POST /auth/device-proof for restricted-session device binding with single-use challenge and exact account/session/service context. No endpoint may accept a content master key, raw device private key, R, PRF secret output, or plaintext unlock phrase.

## 3. Identity and devices

| Method / route | Purpose |
| --- | --- |
| GET /accounts/{id}/identity | Public identity for an authorized invitation/member workflow; not an unrestricted directory |
| GET /me/devices | Current account device view and certificates |
| GET /accounts/{id}/roster?after=... | Signed roster chain for authorized related accounts |
| POST /me/enrollments | New pending device request |
| GET/POST /me/enrollments/{id}/relay | Bounded opaque pairing messages, transcript commitments |
| POST /me/enrollments/{id}/approve | Submit signed provisional certificate after OOB verification; no active roster publication yet |
| POST /me/enrollments/{id}/confirm | New device proves possession and completes single-use flow |
| POST /me/devices/{id}/revoke | Signed roster event plus immediate session revocation |
| POST /me/recovery-challenge | Restricted authenticated session obtains current generation/head and single-use nonce |
| POST /me/recovery-reset | Root-signed CAS reset and new-device proof; atomically upgrade current session and revoke others |

An authenticated but untrusted device may access only minimal account/security and enrollment/recovery state; no group inventories or ordinary device/recovery group-key envelope endpoints are available until activation. It must not enumerate all shared files or issue group writes. A revoked device cannot retrieve new key envelopes or data even if its account session was previously valid.

## 4. Groups and keys

| Method / route | Purpose / permission |
| --- | --- |
| GET /groups | Only groups accessible to the active account/device |
| POST /groups | Signed private/shared genesis, encrypted metadata, initial envelopes |
| GET /groups/{id}/policy | Signed genesis and policy chain, paginated |
| POST /groups/{id}/policy-events | Owner-signed membership/settings/archive changes |
| POST /groups/{id}/ownership-transfer | Both identities' consent, recent auth |
| GET /groups/{id}/key-envelopes | Trusted current member: own device or own account recovery-recipient envelopes, scoped by epoch |
| POST /groups/{id}/invitations | Owner-signed pending admission intent targeting exact account root |
| POST /group-invitations/{id}/accept | Trusted target account signs acceptance; no access activated yet |
| POST /group-invitations/{id}/decline | Trusted target declines pending admission |
| POST /groups/{id}/transitions | Create bounded staging descriptor for membership/epoch/checkpoint operation |
| PUT /groups/{id}/transitions/{tid}/pages/{index} | Idempotent bounded immutable ciphertext/envelope/inventory page |
| POST /groups/{id}/transitions/{tid}/commit | Atomically bind page commitment, signatures, expected heads and recipient set |
| POST /groups/{id}/key-distributions | Same-account device grants or authorized full-history invitation grants |
| POST /groups/{id}/epoch-transitions | Owner/editor optional rekey or member-executed mandatory roster-only rekey; exact expected state |
| POST /groups/{id}/purge | Owner-signed permanent deletion; retention and operational backup limits disclosed |

The service validates the requesting actor, signed current authorization, recipient set, and immutable context. A client independently does the same. A group ID in a route cannot override another signed group ID in the body.

## 5. Threads and entries

| Method / route | Purpose |
| --- | --- |
| GET /groups/{id}/threads | Paginated encrypted metadata/references |
| POST /groups/{id}/threads | Signed creation with encrypted title |
| GET /threads/{id}/entries | Paginated encrypted entry heads |
| POST /threads/{id}/entries | Signed initial revision |
| GET /objects/{id}/revisions | Authorized retained immutable versions |
| POST /objects/{id}/revisions | Compare-and-swap or explicit conflict branch |
| POST /objects/{id}/tombstone | Signed soft delete |
| POST /objects/{id}/restore | Signed restore as new state/revision |
| GET /groups/{id}/trash | Authorized deleted-object metadata/ciphertext |

No /search?q=plaintext route. Search is client-side. Server filters may use permitted metadata such as group/type/sequence only. Private tags and text remain encrypted.

## 6. Files

| Method / route | Purpose |
| --- | --- |
| POST /groups/{id}/uploads | Reserve bytes, bind upload to device/group/new file version |
| GET /uploads/{id} | Missing part list, acknowledged digests, expiry, reservation |
| PUT /uploads/{id}/parts/{index} | Bounded binary ciphertext body, expected length/digest |
| POST /uploads/{id}/commit | Signed encrypted manifest and exact part inventory -> committed unattached version |
| GET /me/unattached-files | Recoverable committed versions uploaded by this account, still in currently accessible groups, awaiting entry publication |
| DELETE /files/{version}/unattached | Current uploader/writer or owner explicitly removes an unreferenced committed version; reference/retention checks required |
| DELETE /uploads/{id} | Cancel/release reservation idempotently |
| GET /files/{version}/manifest | Authorized signed encrypted manifest |
| GET /files/{version}/chunks/{index} | Authorized ciphertext part delivery |
| GET /groups/{id}/files | Paginated attachment/file-version metadata |

Chunk endpoint rejects out-of-range index, oversize length, content mismatch on retry, expired session, wrong account/device/group, quota exhaustion, and invalid phase. Size is verified from bytes received, not only Content-Length. Endpoint must be safe for HTTP/2 and interrupted streaming. Store ciphertext only.

## 7. Synchronization and maintenance views

- GET /sync?cursor=...&limit=... returns scoped transport events plus next cursor and retention/resync information.
- POST /snapshots creates a complete account-authorized resync/export inventory at one watermark, including the hidden private namespace and selected/currently accessible groups. It is the normal full-account bootstrap route.
- POST /groups/{id}/snapshots creates a scoped group inventory with purpose, watermark, bound token, and expiry. For combined multi-group export/resync use one account snapshot; do not combine unrelated watermarks as if they were atomic.
- GET /snapshots/{id}/pages?cursor=... reads immutable inventory after current authorization checks.
- POST /snapshots/{id}/renew extends only an authorized bounded export lease.
- DELETE /snapshots/{id} releases the lease/pins idempotently.
- GET /mutations/{operation_id} returns an authorized device-scoped receipt to resolve an ambiguous commit before changing request bytes.
- POST /sync/ack records transport progress if needed; it is not proof the user read content.
- GET /me/storage and GET /admin/storage show appropriate quota aggregates.
- POST/DELETE /me/notification-subscriptions manage device-bound generic push endpoints.
- GET /health/live exposes minimal liveness; readiness/dependency detail is operator-restricted.

Every sync event reference is reauthorized on fetch. Removal notice may be delivered to the removed account without leaking new group content. Do not silently drop the only indication that local access should be disabled.

## 8. Required envelope shape

A content mutation request contains a strict typed header, ciphertext nonce/body, encrypted DEK wrap, detached signature, and operation ID. The signed header includes object/group/revision, parent list, author device, membership/epoch references, payload version, ciphertext digest/length, and exact operation kind. Response includes authoritative commit receipt, resulting heads, server sync sequence, and idempotency correlation. Server timestamps are separate from signed author claims.

P02 must provide complete schemas and sample fixtures; P03/P04 generate OpenAPI and fail tests on schema drift. All schemas specify maximum lengths and unknown-field behavior. Trusted production clients must never submit plaintext/base64-only placeholders; client tests and recipient verification enforce this. The server cannot distinguish arbitrary validly framed opaque bytes from genuine encryption.

## 9. Error model

Use a consistent JSON object: error.code, safe message key, request_id, retryable, and bounded structured details. Never include stack traces, SQL, plaintext, tokens, or internal paths.

| Status | Examples |
| --- | --- |
| 400 / 422 | MALFORMED_ENVELOPE, UNSUPPORTED_SCHEMA, INVALID_SIGNATURE, INVALID_CHUNK |
| 401 | AUTH_REQUIRED, SESSION_EXPIRED |
| 403 | DEVICE_NOT_TRUSTED, DEVICE_REVOKED, ROLE_FORBIDDEN |
| 404 | Object missing or inaccessible where existence should not be disclosed |
| 409 | STALE_REVISION, STALE_MEMBERSHIP, REKEY_REQUIRED, IDEMPOTENCY_MISMATCH |
| 410 | ENROLLMENT_EXPIRED, UPLOAD_EXPIRED, SYNC_CURSOR_EXPIRED |
| 413 | REQUEST_TOO_LARGE, FILE_LIMIT_EXCEEDED |
| 429 | RATE_LIMITED with Retry-After |
| 507 | QUOTA_EXCEEDED or STORAGE_UNAVAILABLE, safely distinguished |
| 503 | TEMPORARY_UNAVAILABLE with bounded retry hints |

Never retry signature errors indefinitely. Backoff applies to transient errors; conflicts require reconciliation. Do not confuse an unknown device's missing key with corrupted ciphertext.

## 10. Idempotency and concurrency

Every retryable control mutation uses an idempotency key scoped to actor/account/device and operation family. Store a canonical request digest; the same key and body returns the same result, while another body returns 409. Retain receipts at least 30 days; immutable IDs/version preconditions still prevent duplicate effects afterward.

Use expected revision/policy/roster heads as concurrency controls, checked in the commit transaction. Signed authorization alone does not make a stale mutation current. Chunk retries with identical ciphertext are idempotent; a changed part at the same index is rejected and requires a new upload/version.

## 11. Signed semantic fields and encrypted payload limits

Freeze explicit schemas for group metadata, thread metadata, entry body/checklist, tombstone, restore, file manifest, identity/roster/policy, checkpoint, key distribution and mutation receipt. Each includes schema version and all semantically required fields with length bounds. The signed public operation context binds thread/parent relation, attachment version list, operation kind, conflict parents, expected policy/epoch, and any archive/delete state. The receiver compares matching encrypted fields before using them. A signature over ciphertext without its relationship/attachment context does not protect placement in a thread.

The server can reject malformed framing, signatures, lengths and authorization. It cannot determine whether arbitrary opaque ciphertext is genuine encryption of a valid note. Prevent plaintext placeholders in trusted client implementations through tests, and reject invalid/decrypted schemas on receiving clients; do not invent server-side content inspection as an E2EE compliance check.

Do not expose an arbitrary account directory. Use exact opaque identity-contact cards (account ID, fingerprint, public identity) shared out of band; GET /accounts/{id}/identity permits an authenticated active user making a rate-limited exact lookup without revealing group/device inventories. Group owners still verify the fingerprint. Root identity replacement is not a normal profile edit.

Additional errors: SESSION_DEVICE_PROOF_REQUIRED, RECOVERY_GENERATION_CONFLICT, TRANSITION_EXPIRED, SNAPSHOT_EXPIRED, REKEY_RESTART_REQUIRED, UNANCHORED_HISTORY, EXPORT_TRUNCATED, KEYS_PENDING, HISTORY_CLOSURE_REQUIRED, ROSTER_CHANGED, POLICY_CHANGED, INTEGRITY_FAILURE, RESTORE_QUARANTINE, RESOURCE_LIMIT, INSUFFICIENT_STORAGE and ACCESS_REVOKED. Phase P02 maps these to fixed HTTP codes and retry semantics; local-only export/integrity errors use the same typed namespace without pretending they are server responses. Keep business errors distinguishable in UI, but unauthorized resource existence remains concealed. All paginated/JSON responses have byte ceilings as well as item ceilings; 1,000 large encrypted notes cannot be returned as one unbounded response.
