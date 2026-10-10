# Windows Hello implementation and developer handoff

Updated: 2026-10-09. Repository: `kurasis/passkeylocal`.

This is a standalone implementation brief for a developer or another coding
assistant. It explains the working design, its boundaries, the failures that led
to it, and how to extend or port it without repeating those failures. Read this
file first; use the linked source for exact behavior. Historical diagnostic
documents describe earlier increments and are not the current enrollment API.

## 1. Current result and scope

Windows Hello is connected to the **password vault** in the existing Tauri 2
desktop application. It is an optional, experimental alternative to typing the
master password. The same KDBX engine and independent password recovery remain
in use. The password-vault baseline described here has a separate scope from File Safe.
The subsequent [File Safe integration](../file-safe/WINDOWS_HELLO.md) reuses its
PRF/TPM mechanism with a different protected secret, purpose, key/RP, journal and
native session. Its root never reaches the renderer. Browser biometrics remain
a separate adapter; the owner feedback below applies only to the password vault.

The deployed implementation was introduced by
[PR #32](https://github.com/kurasis/passkeylocal/pull/32):

- Tested installer source: `c18894e210a07546ba66cf178b8048ae5c40ac61`.
- Merge: `6185e8008c8f1b943cb61de61ac2e7c8875d2523`.
- Download/evidence publication: `5ddaef9e1066b52e01aac50d7d9ec4e0de537e8e`.
- Installer and checksums: [Windows download folder](../../deploy/windows-desktop/).

After receiving that installer, the owner replied **«работает»** (“works”) on
2026-10-09. Treat this as owner confirmation that the delivered Hello flow works
on their computer. It did not include a new source-stamped report, selected
lifetime, prompt count, restart/expiry matrix or negative-case results. Do not
invent those details or claim comprehensive physical acceptance.

Previously identified target: Windows 11 Pro 25H2, OS build family 26200,
native WebAuthn API 9, Kensington VeriMark Desktop. A complete current Windows
revision and driver version were not supplied. Windows owns fingerprint/face/PIN
verification. The application does not read fingerprints, guarantee fingerprint
only, identify the reader's serial number, or implement Apple's Face ID API.

The owner excluded a manual test using another Windows account on the same PC.
That exclusion remains in effect; account isolation is not thereby proven.
Do not request unchanged diagnostic reruns or reset Hello/TPM as routine setup.

## 2. The design that works

Use **native WebAuthn PRF plus a separate Platform KSP TPM key**. These solve
different problems:

| Layer | Role | What it does not establish by itself |
| --- | --- | --- |
| Hello WebAuthn credential, user verification required | Produces a credential-associated PRF secret after OS authorization | A display name, platform attachment or successful dialog is not per-key TPM evidence |
| HKDF-SHA-256 and AES-256-GCM | Uses that secret to authenticate/decrypt the outer envelope | Does not independently bind data to this TPM |
| Platform KSP RSA-2048, OAEP/SHA-256 | Protects the inner secret with a locally verified, non-migratable TPM object | Its decrypt operation alone does not require a fresh Hello gesture |
| Existing KDBX engine | Authenticates/decrypts the actual current vault | A native “success” boolean cannot replace KDBX authentication |

The native enrollment envelope is conceptually:

```text
P = the KDBX engine's 32-byte password-only credential component
S = a fresh 32-byte random enrollment salt
R = native WebAuthn PRF(owned credential, S), with OS-required user verification
K = HKDF-SHA256(ikm=R, salt=S, info="PassKeyLocal.VaultHello.v1", length=32)
I = RSA-OAEP-SHA256-encrypt(TPM public key, P)       # 256 bytes
C = AES-256-GCM-encrypt(K, random 12-byte nonce, I, AAD=serialized Header)
```

For unlock: obtain fresh `R`, authenticate/decrypt `C`, use the exact TPM private
key to decrypt `I`, and pass recovered `P` to the live crypto worker. The worker
must open the real KDBX and verify its current generation/hash before exposing
an unlocked session. Do not cache `R`, `K` or plaintext `P` for later unlocks.

`P` is a **password-equivalent secret** for this password-only vault profile,
not a harmless public hash, and not the final KDBX encryption key. Obtain it
through the existing engine's credential API after authenticating the password;
do not add an ad hoc password-to-key implementation. A port supporting key files,
multiple credential components or a different database format must redesign
this boundary for its own credential semantics.

The GCM ciphertext is 272 bytes including its tag. The authenticated Header
contains the domain/version, random enrollment UUID, local vault owner/credential
epoch, mode, creation/expiry times, salt, credential ID, TPM public area and Name.
Its serialized bytes are part of the cryptographic format: changing ordering,
encoding, fields or domain requires an explicit compatibility/migration decision.
Lifecycle fields `ready` and `last_seen` are outside that Header; they are not
TPM monotonic counters or a whole-profile rollback defense.

## 3. Threat model and non-negotiable boundaries

This design trusts Windows, the native WebAuthn API, KSP/TBS and the running
application. Local TPM evidence is verified through that trusted stack; this is
not remote AIK attestation or protection against an administrator/kernel attacker
controlling the OS. A compromised unlocked process can reach secrets. The
renderer-to-worker transport also belongs to the trusted application; keeping
secrets out of UI state does not make that transport immune to process compromise.

Preserve these requirements:

1. Master-password KDBX recovery remains independent of Windows, TPM, passkeys,
   this app and its metadata. Never replace the vault password with a Hello key.
2. An authorization dialog or `UserConsentVerifier` success is not a decrypt
   capability. Never implement `if (verified) unlockWithCachedSecret()`.
3. Do not use DPAPI alone, an exported software private key, plaintext disk cache,
   signature-derived AES keys, or a silent fallback when PRF/TPM fails.
4. Keep master-password strings out of native IPC. Do not persist a component,
   PRF output, derived AES key, or a hash of the component as a new offline verifier.
5. No secret material in diagnostics, telemetry, clipboard, screenshots, errors,
   Git or artifacts. Credential IDs, key names and envelopes also do not belong
   in ordinary support logs. Existing published fixtures are synthetic.
6. Do not clear TPM, change ESS/Windows security policy, enroll an AIK, disable
   security features, or delete general Windows/passkey containers to repair the app.
7. Never infer enrollment eligibility from historical `eligible`/`remaining`
   fields. Old reports preserve their original conservative flags.
8. Keep desktop and PWA outputs separate. Native IPC, native envelope handling and
   native worker implementations must not enter the Cloudflare bundle.

## 4. Source map: reuse the existing implementation

Paths below are relative to the repository root. Some reusable adapters retain
historical names such as `Probe` or `combined`; production enrollment deliberately
uses them with separate owned namespaces.

| File | Responsibility |
| --- | --- |
| [hello/enrollment.rs](../../apps/desktop/src-tauri/src/hello/enrollment.rs) | Fixed command types, authenticated envelope, state machine, lifetime, bounded journal, invalidation and cleanup |
| [hello/enrollment/windows.rs](../../apps/desktop/src-tauri/src/hello/enrollment/windows.rs) | Connects that state machine to native PRF and TPM operations; zeroizing reply |
| [hello/prf/windows.rs](../../apps/desktop/src-tauri/src/hello/prf/windows.rs) | Native capability/routing, creation/assertion, UV/context checks, cancellation and buffer handling |
| [hello/prf/windows/combined.rs](../../apps/desktop/src-tauri/src/hello/prf/windows/combined.rs) | Reopen and delete only the credential owned by the journal's RP and random user |
| [hello/tpm/windows.rs](../../apps/desktop/src-tauri/src/hello/tpm/windows.rs) | Platform KSP key creation, policy readback and RSA operations |
| [hello/tpm/windows/combined.rs](../../apps/desktop/src-tauri/src/hello/tpm/windows/combined.rs) | Reopen the exact key and compare its public area/Name; exact-object deletion |
| [hello/tpm/windows/read_public.rs](../../apps/desktop/src-tauri/src/hello/tpm/windows/read_public.rs) and [parser](../../apps/desktop/src-tauri/src/hello/tpm/read_public.rs) | Provider-owned TBS access and bounded TPM2_ReadPublic verification |
| [host.rs](../../apps/desktop/src-tauri/src/host.rs) | `hello_enrollment`, trusted window/HWND, storage token, concurrency and lock-generation guards |
| [storage.rs](../../apps/desktop/src-tauri/src/storage.rs) and [filesystem.rs](../../apps/desktop/src-tauri/src/filesystem.rs) | Native vault binding, atomic storage, path/link/ACL controls |
| [desktop hello-vault.ts](../../apps/desktop/src/hello-vault.ts) | Worker-only fresh-password verification, component transport and actual KDBX unlock |
| [worker-storage.ts](../../apps/desktop/src/worker-storage.ts) and [platform.ts](../../apps/desktop/src/platform.ts) | Narrow native bridge, session ownership and discarded/cleared late replies |
| [vault-core session.ts](../../packages/vault-core/src/session.ts) | `unlockWithPasswordHash`, exact current-head checks and decrypted-session publication |
| [hello-vault-protocol.ts](../../apps/pwa/src/hello-vault-protocol.ts) and [worker handlers](../../apps/pwa/src/worker/handlers.ts) | Nonsensitive status/modes and worker operations |
| [ui/hello-vault.tsx](../../apps/pwa/src/ui/hello-vault.tsx) | Settings enrollment/revoke and explicit locked-screen unlock |
| [capabilities/main.json](../../apps/desktop/src-tauri/capabilities/main.json) and [build.rs](../../apps/desktop/src-tauri/build.rs) | Allowed Tauri command registration |

Do not wire the UI to the older `hello_enroll`/`hello_unlock` diagnostic stubs.
The active-vault native command is **`hello_enrollment`**; the public worker
operations are `helloVaultStatus`, `enableHelloVault`, `unlockHelloVault` and
`disableHelloVault`.

## 5. Native WebAuthn: details that matter

1. Dynamically load `webauthn.dll` only from System32. Missing exports or an older
   API must disable this path without preventing ordinary password startup.
2. Read the actual API version. This implementation requires **API 9+** for its
   explicit authenticator-routing contract. API 9 is not the first PRF API, and
   Windows “25H2” or API presence alone does not prove a usable PRF credential.
3. Select one unambiguous, unlocked `Windows Hello` candidate. The display name
   and authenticator ID are routing hints under the trusted-OS model, not an
   attestation certificate. Reject ambiguity instead of guessing.
4. Creation uses options version 9, platform attachment, resident credential,
   ES256 (`-7`), user verification required, a fresh random challenge and
   attestation `none`. Supply **both `bEnablePrf = TRUE` and `pPRFGlobalEval`**
   containing the 32-byte input during creation. Enabling PRF without that
   evaluation input has a known Windows interoperability failure.
5. For assertions use the exact created credential in a one-element allowlist,
   the selected route, UV-required, a fresh challenge, and
   `pHmacSecretSaltValues`. Keep default WebAuthn PRF domain separation; do not
   switch between raw HMAC-secret and PRF semantics.
6. Validate result structure version, internal transport, exact credential ID,
   RP hash, user-presence/user-verification flags, no backup eligibility/state,
   and exactly one 32-byte PRF result. Creation must bind its returned ID to
   authenticator data. Reject malformed/null/oversized outputs before copying.
7. Reuse the tested authenticator-data parser. The fixed header is 37 bytes,
   AAGUID is 16 bytes, credential-ID length occupies offsets 53–54, and the ID
   starts at 55. The earlier parser was wrong by two bytes. A test that repeats
   the same erroneous layout is not independent verification.
8. Own the Windows dialog with the real main HWND. Preserve the scoped
   cancellation GUID/watcher, 60-second ceremony deadline and DLL/buffer lifetimes
   until the native call returns. An OS response arriving after invalidation
   must never unlock, even if Windows reports success.
9. Free API allocations with their matching API functions. Wipe bounded secret
   output buffers before disposal; do not log native structures.

Use the checked-in generated [bindings](../../apps/desktop/src-tauri/src/hello/prf/bindings.rs),
[generator](../../tools/webauthn-bindings/) and independent
[Microsoft-header ABI reference](../../tests/hello/vendor/README.md). App Rust is
pinned separately from the binding generator. Never hand-extend an old FFI
structure or assume its layout from one example. Windows CI checks every used
size/offset against an MSVC-compiled official header.

This is a local native API integration with an app-reserved RP/origin, not a
remote WebAuthn login server. It does not implement an independent assertion
signature verifier or remote attestation service. A server-authentication port
requires its own challenge/origin/signature/counter policy and threat model.

## 6. TPM binding: verify the key, not just the provider

Use Microsoft Platform Crypto Provider, not Microsoft Passport Key Storage
Provider, for the inner RSA key. Create a unique, per-user RSA-2048 decrypt-only
key with export policy zero. Verify readback and hardware/TPM 2 capability.
Provider-wide “hardware” flags alone are insufficient.

The local per-key proof must:

- Borrow the provider-owned TBS context with pointer-width semantics and the
  key's virtualized TPM handle as a DWORD. Keep their owner handles alive.
- Send only the fixed `TPM2_ReadPublic` command (`0x173`) through that context;
  no arbitrary TPM command or handle may come from IPC.
- Bound and parse the response; reject wrong tags/sizes/errors/trailing bytes
  and unsupported templates. Match the RSA modulus/exponent to the CNG public key.
- Require generated, non-migratable decrypt-object attributes, including
  `fixedTPM`, `fixedParent` and `sensitiveDataOrigin`. Recompute the Name from the
  exact TPMT_PUBLIC and compare it to both TPM output and the PCP property.
- On every reopen, repeat policy/public/Name validation and compare against the
  enrollment's authenticated public data. A matching key name is insufficient.
- Never close or flush the borrowed TBS context/TPM object; the provider owns them.

Owner measurement observed attributes `132210` (`0x00020472`), including decrypt,
fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth and noDA. `userWithAuth`
does not mean fresh Hello authorization. `noDA` is not evidence of a fingerprint
prompt. Qualified-Name shape checking is not parent-chain certification.

The PCP usage property uses a different namespace from generic CNG usage. The
owner returned `65538` (`0x00010002`): separate the low usage kind from the known
high flag and apply the source's explicit allowlist. Do not compare the entire
DWORD to `2`, ignore every unknown flag, or derive the physical TPM version from
the historical high-flag name. Obtain TPM version independently from TBS.

Wrap with the public-RSA helper and decrypt with the Platform KSP key using
OAEP/SHA-256. Do not change padding to make an unrelated Passport test pass.
Delete only the exact journal-owned key; the current adapter uses
`NCryptDeleteKey(handle, 0)` and verifies absence by reopening. See
[local proof details](HELLO_LOCAL_TPM_BINDING.md) for assumptions and sources.

## 7. Enrollment, unlock and deletion sequence

### Enrollment

1. Require a current unlocked, writable, committed vault with no unsaved changes.
   Ask for the master password again and authenticate the exact committed KDBX
   inside the crypto worker. A wrong password must stop before native creation.
2. Extract the engine's 32-byte component, release temporary credentials and send
   only the component, selected mode, generation and ciphertext SHA-256 to native.
3. Native independently resolves the store owner, credential epoch and current
   head. Verify the caller's generation/hash and current native session.
4. Generate an enrollment UUID and salt. Write a non-ready ownership journal
   **before** creating either native object. Refuse a new enrollment if an old
   journal still needs cleanup.
5. Create/verify the TPM key and owned PRF credential. Save updated ownership
   metadata, wrap the component in TPM, then seal that ciphertext with PRF/GCM.
6. Perform a separate fresh PRF assertion, open both layers and compare the
   recovered component in constant time. Recheck session, head and deadline.
7. Only then mark the record ready. Clear temporary component/PRF/key buffers on
   success and failure. On failure invalidate and attempt exact-object cleanup;
   preserve a retryable cleanup journal if deletion fails.

Creation and round-trip authorization may produce more than one Windows prompt.
Do not promise a fixed count or remove the verification round trip to reduce it.

### Unlock

1. Require an explicit user action; no automatic biometric loop or retry on cancel.
2. Validate the journal, local vault/epoch, lifetime and observed clock order.
   Capture the current exact generation/hash and session/revocation generations.
3. Reopen and validate the exact TPM key and owned credential. Obtain a fresh
   PRF output with required OS user verification.
4. Authenticate/decrypt GCM, then decrypt the inner RSA ciphertext. Recheck the
   session, vault/head, generations and deadline before releasing the component.
5. Deliver it only through the live worker bridge. Open the actual current KDBX
   and recheck its head after asynchronous work. Publish unlocked UI state only
   when KDBX authentication and all freshness checks succeed.
6. Clear transport arrays and temporary buffers, including errors and late
   replies to a terminated worker. JavaScript cannot guarantee total memory
   erasure; do not claim otherwise.

### Revocation and credential-changing writes

First advance the revocation generation and make the record durably non-ready,
clearing ciphertext and the memory envelope. Then attempt deletion of **both**
owned objects and verify absence. Remove the journal only after successful
cleanup. Destructors for temporary reopened handles must not delete a persistent
enrollment accidentally.

Password change, confirmed vault replacement/import and snapshot restore revoke
the previous enrollment **before** committing the credential-changing write.
Ordinary content saves retain it; generation/hash bind an individual operation,
while vault owner/credential epoch bind the enrollment's lifetime.

If durable invalidation succeeds but object deletion fails, the current code
reports `HELLO_CLEANUP_REQUIRED` and permits the credential-changing write. The
remaining objects stay visible for cleanup retry. If durable invalidation itself
fails, do not proceed with the write. Busy native operations invalidate pending
results and make conflicting writes retryable rather than racing old credentials.

## 8. Persistence, lifetimes and command contract

Owned namespaces in this application:

```text
RP:              vault.passkey-local.desktop.invalid
TPM key:         PassKeyLocal.VaultHello.<random enrollment UUID>
AEAD/HKDF domain: PassKeyLocal.VaultHello.v1
Journal:         <per-user app data>/hello-vault/enrollment.json
```

The credential user handle is derived from the domain and random enrollment UUID,
not the Windows user name. Journal that identity before creation. Recovery can
find a credential whose ID was not returned by using **both** the exact RP and
that random user handle. Never delete all credentials under an RP or enumerate
unrelated RPs for cleanup. Diagnostics use separate namespaces.

For another product, choose its own fixed RP, key prefix, domain and storage path;
do not adopt this app's existing objects. For an upgrade of this app, changing
those constants is a migration and cleanup problem, not a cosmetic rename.

The journal is strict, bounded to 16 KiB, atomically replaced, protected by per-user
ACLs, and accessed with the existing link/reparse-point and directory-pinning
checks. Hello metadata is never included in portable KDBX backups.

| Mode on the wire | Behavior |
| --- | --- |
| `session` (default) | Envelope in native process memory only, at most 24 hours; disk retains non-ready ownership metadata with zero nonce/empty ciphertext |
| `remember6` | Encrypted envelope persists for six hours from enrollment |
| `remember12` | Encrypted envelope persists for twelve hours from enrollment |
| `remember24` | Encrypted envelope persists for twenty-four hours from enrollment |

An unlock does not extend the deadline. Session-mode app exit/crash loses the
envelope; next launch requires the password and cleanup before reconnecting.
Expiry or observed backward clock movement makes the record nonresumable.
This is application-clock policy, not a TPM expiration policy or defense against
restoring an entire older system/profile snapshot. Lifetime and inactivity lock
are distinct settings.

The native `hello_enrollment` request is a fixed tagged union:

```text
status: { operation: "status" }
enroll: { operation: "enroll", mode, generation, sha256, component: [32 bytes] }
unlock: { operation: "unlock" }
revoke: { operation: "revoke" }
```

Every call also carries the live native storage-session token. Never add caller
paths, key names, RP IDs, arbitrary ciphertext or arbitrary decrypt commands.
Status is `off`, `enabled` or `cleanup-required`, with nullable mode/expiry.
Only a successful native unlock may return a component and binding to the worker;
the screen-facing worker result contains no component.

Enforce the trusted local main window, focus for enrollment/unlock, actual HWND,
single-flight, native token/deadline and pre/post lock/revocation generations.
Allow legitimate OS-owned dialog focus transfer; minimize, Windows session/power
lock, inactivity and worker disposal still invalidate pending results.

Rust/serde pitfall found in this feature: internally tagged **unit** variants may
ignore extra fields despite the enum's `deny_unknown_fields`. Keep no-argument
actions as empty **struct variants** (`Status {}`, `Unlock {}`, `Revoke {}`) and
retain the negative-input regression test.

## 9. Failed approaches and error interpretation

| Observation in this project | Correct interpretation / action |
| --- | --- |
| Hello consent succeeds, vault remains locked | Consent is not protected unwrap. Implement the PRF/TPM path and real KDBX opening. |
| Passport OAEP decrypt returns `0x80090027` (`NTE_INVALID_PARAMETER`) even after fingerprint | That candidate did not establish OAEP support. Preserve operation context; do not diagnose a defective reader or treat this as authorization denial. Platform KSP OAEP is a separate tested path. |
| Passport PKCS#1 v1.5 succeeds | A compatibility result, not approval to downgrade the production envelope or infer TPM binding. |
| Private export returns `0x8009000A` (`NTE_BAD_TYPE`) for several formats | Unsupported export format is not explicit export refusal or per-key hardware proof. Do not mark the probe passed. |
| Subject-only `NCryptCreateClaim` returns `0x80090027` | This claim attempt is unavailable on the measured route; no attestation was verified. |
| Direct WebAuthn attestation requested, Windows returns `fmt: none` | A direct preference does not guarantee attestation. Do not loop, reset TPM, or treat `none` as a verified certificate. Use the separate local TPM proof within its stated threat model. |
| PRF capability succeeds, `prf-created-credential-context` fails | Inspect creation input and independent authenticator-data parsing. The observed parser bug was the two-byte offset error; capability alone was never enough. |
| PCP usage is `65538`, expected `2` | Decode usage kind and supported flags separately; preserve strict rejection of unknown combinations. |
| Delete with silent flag returns `0x80090009` (`NTE_BAD_FLAGS`) | Use the supported exact-key deletion call with flags zero, then verify absence. |
| Cancellation returns `0x80090036` | On the observed WebAuthn operation this is cancellation. Stay locked, clear transient data, preserve retry/cleanup state; do not silently try another method. |
| Exact key reopen after deliberate deletion returns `0x80090016` (`NTE_BAD_KEYSET`) | Expected absence in a controlled deletion test, not a successful unwrap. In ordinary unlock, require password recovery. |
| Hosted runner has API 7 / no Hello device | Expected inability to run physical PRF/TPM flow. Run boundary/software tests, report hardware untested, and keep master-password startup working. |
| Exact label lookup cannot find the lifetime select although it is visible | Keep a separate explicit label/control association; nesting all option text in the label caused the packaged-form regression. |

Error codes are operation-specific evidence, not universal success/denial rules.
Keep a static operation name, source commit and sanitized code in diagnostics;
never include the offending secret or serialized native request.

## 10. Evidence already obtained and what remains

Detailed originals are linked from the [release ledger](../RELEASE_EVIDENCE.md)
and [owner acceptance record](HELLO_OWNER_ACCEPTANCE.md). Preserve their bytes.

| Evidence | Established scope |
| --- | --- |
| PRF `72a0df6` | Creation, repeated/same/changed input, AES round trip and cleanup; owner reported a fingerprint at creation and all three assertions |
| Local TPM `bbead07` | Exact-key ReadPublic/public/Name checks, OAEP, reopen, negative controls and cleanup; local trusted-stack evidence |
| Combined `a7f56d8` | Preparation and fresh-process resume; owner reported two fingerprint confirmations for each button; separate cancel/cleanup reports |
| Key loss `4b3ba34` | Owned passkey/TPM removal, exact absence and cleanup |
| Copy `cdcc954` | Envelope failed to find both keys on another Windows installation, then opened on the source; correlated file digest, not private-container transfer or another-account proof |
| KDBX recovery `9200a4b` | 27 stages passed: real public fixture opened/resaved through the component, keys removed, wrong password rejected and records/history recovered independently |
| Installer `c18894e` | All 11 CI checks; 167 Windows and 135 Linux routine native tests, 174 TypeScript tests, 46 desktop/browser scenarios, eight production PWA scenarios, installed-app boundary/form checks |
| Owner “works”, 2026-10-09 | Basic delivered application Hello flow reported working; no new detailed per-scenario evidence |

Synthetic passes do not automatically certify every production lifecycle path.
Do not request the above unchanged experiments again. New work needs tests for
its changed behavior; broader physical acceptance still includes remembered
restart/expiry, revocation/password rotation/restore, interruption/lockout and
standard-user/ESS/sensor variations. Same-PC/other-account manual testing remains
excluded and unverified. No remote AIK or PRF-secret hardware-attestation claim
has been established.

## 11. Verification plan for future changes or a new port

Start from the existing tests; do not create tests that merely repeat your own
parser's assumptions. Use synthetic vaults and keys, never the owner's real vault.

| Area | Minimum behavior to retain |
| --- | --- |
| Native lifecycle | Session memory-only persistence, remembered reopen, fresh authorization per unlock, expiry/clock rollback, authenticated-header/ciphertext tamper, wrong vault/epoch/head, stale completions, cancellation, failed creation/deletion, cleanup retry and strict command input |
| KDBX worker | Wrong password stops enrollment before IPC; recovered component opens actual current KDBX; wrong component/head fails; normal save/history and independent password recovery survive; rotation and lock-during-open reject stale results |
| Bridge/UI | Only explicit unlock; cancel has no retry; no component in screen state; late native result after worker termination is cleared; all four modes and default session work; exact accessible labels and responsive layouts |
| Native ABI/protocol | Pinned generated bindings match independent Microsoft-header sizes/offsets; independent public wire fixtures test parser boundaries and malformed data |
| Installed Windows app | Native command registered and narrowly permitted, off/no-record revoke safe, malformed/stale-session requests refused, real worker populates settings; installer binary/source/checksum correlation |
| Separation/recovery | PWA contains no native enrollment IPC; Windows/PWA KDBX and independent Python recovery remain compatible; File Safe is unchanged unless separately scoped |

Relevant tests:

- [Native enrollment cases](../../apps/desktop/src-tauri/src/hello/enrollment/tests.rs).
- [Real KDBX worker cases](../../apps/pwa/test/hello-vault.test.ts).
- [Desktop UI/worker bridge cases](../../apps/desktop/test/ui/hello-vault.spec.ts).
- [Installed app smoke](../../apps/desktop/scripts/packaged-smoke.mjs).
- [Independent KDBX recovery interop](../../apps/desktop/test/hello-recovery-interop.ts).
- [Public authenticator-data fixture](../../tests/hello/authenticator_data_fixture.py).
- [Windows workflow](../../.github/workflows/windows.yml) and [general CI](../../.github/workflows/ci.yml).

From the repository root, ordinary development checks include:

```sh
npm ci
npm run typecheck
npm test
cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check
cargo test --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
cargo clippy --locked --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
npm run build -w @passkey-local/pwa
npm run desktop:frontend
node apps/desktop/scripts/check-bundles.mjs
npx playwright test --config apps/desktop/test/ui/playwright.config.ts
```

Use the repository's pinned Node/Rust/Python dependencies and platform setup.
Linux tests/cross-compilation do not replace Windows MSVC/runtime checks. Follow
the Windows workflow for signed build inputs, independent ABI/interop/resource
gates, NSIS installation and artifact provenance. The packaged smoke script is
explicitly restricted to an ephemeral GitHub-hosted runner; do not run it on the
owner's normal profile or weaken that guard. No installer rebuild is needed for
a documentation-only change such as this handoff.

For **new physical application acceptance**, use a disposable password vault in
the existing Windows account. Record app source, OS/API and selected mode. Check
enroll → lock → explicit Hello unlock, cancel → still locked, a saved entry/history
after unlock, and ordinary password opening of an exported backup. Separately
measure remembered restart/expiry and disable/password-change/restore behavior
when those cases are in scope. Record actual prompts without assuming fingerprint
instead of PIN. Do not count a mock or hosted API-unavailable result as physical
success. Keep the owner's already completed evidence intact.

## 12. Primary references and research trail

These are the references used by the existing implementation, not a claim that
all upstream pages were re-audited on this handoff's update date:

- [W3C WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension).
- [W3C authenticator data](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data).
- [Microsoft native WebAuthn API version](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthngetapiversionnumber).
- [Pinned Microsoft API-9 header](https://github.com/microsoft/webauthn/blob/ef82c157125a0490e05f6ea82a7adb1b8e1bad08/webauthn.h).
- [Bitwarden PR #21998: creation-time PRF evaluation](https://github.com/bitwarden/clients/pull/21998).
- [Repository source review and alternative designs](HELLO_INTERNET_RESEARCH.md).
- [Local TPM binding mechanism and source links](HELLO_LOCAL_TPM_BINDING.md).
- [TPM policy/readback findings](HELLO_TPM_INNER.md).
- [Product integration and lifecycle](HELLO_VAULT_ENROLLMENT.md).
- [Original Windows/Hello requirements](WINDOWS_HELLO_KENSINGTON.md).

Other password managers use different mechanisms; a function named “PRF” may
actually hash a deterministic signature. Review the primitive and threat model,
not the name. Check licenses before importing source into another product; this
repository declares GPL-3.0-only, while the pinned test header has its own MIT
notice. Third-party examples are references, not proof for this implementation.

## 13. Copyable task brief for another coding assistant

```text
Read WINDOWS_HELLO_DEVELOPER_HANDOFF.md first, then inspect the current repository,
its instructions, the linked native enrollment/PRF/TPM code and relevant tests.
The existing Windows Hello password-vault flow works on the owner's target.
Preserve it; implement only the requested extension or explicitly scoped port.

Use native WebAuthn PRF with creation-time evaluation and fresh required user
verification, plus a separately verified Platform KSP TPM inner envelope.
Keep the existing KDBX engine, independent master-password recovery and web build.
Do not substitute consent booleans, DPAPI alone, cached plaintext, signature hashes,
software-key fallback or an unverified provider-wide hardware flag.

Preserve exact-object ownership, journal-before-create, invalidation-before-delete,
current-vault/session/head checks, cleanup retry, bounded IPC/records and secret
clearing. Never expose keys/components in the UI or logs. Keep diagnostic and real
enrollment namespaces separate. Distinguish Windows Hello modality from fingerprint
only, and local trusted-stack TPM proof from remote attestation.

Before editing, identify which lifecycle/boundary changes and which existing tests
cover it. Add independent negative/regression coverage where needed; run checks
appropriate to the change and the required Windows gates. Report exact source and
artifact evidence, actual physical observations and remaining untested scope.
Do not repeat completed owner experiments, request the excluded second-account
test, reset TPM/Hello, alter Windows security policy or fabricate hardware success.

For a port, choose new owned namespaces and map the host/worker/storage/credential
boundaries explicitly. Do not copy PassKey Local's credential component assumptions
into a different vault format without reviewing that format's key semantics.
Do not silently widen the trust model or make unrelated product changes.
```
