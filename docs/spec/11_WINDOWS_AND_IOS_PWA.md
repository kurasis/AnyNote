# Windows Application and iOS PWA

## 1. Supported-platform policy

Windows reference target: a currently supported Windows 11 x64 release with maintained WebView2 Evergreen runtime. Additional Windows/ARM64 support is optional until tested. Do not advertise unsupported Windows versions solely because the binary launches.

iOS reference target: installed Home Screen PWA on currently maintained iOS releases. P01 must establish and publish the minimum supported release and actual device/browser matrix. An API's historical introduction version is not automatically the application's minimum reliable version. Desktop browser access may serve diagnostics/onboarding but is not a substitute for the required Windows app.

## 2. Windows packaging and trust

Use Tauri 2, Rust core, bundled React assets, and WebView2. API responses must remain data, never downloadable scripts or templates. Native capabilities must be explicit, deny-by-default, and limited per window. Preview windows receive no generic filesystem, shell, credentials, or crypto-export capability [SRC-02, SRC-03].

Validate all IPC payloads in Rust: origin/window, operation, account/group IDs, state, size, and arguments. Do not expose general HTTP proxies, arbitrary paths, SQL execution, raw secret retrieval, or arbitrary command execution. A getPrivateKey API must not exist. Returning visible plaintext to the UI is necessary; key custody in Rust does not make the UI immune to plaintext theft if compromised.

Run without administrator rights. Validate navigation and frame navigation; open external links in the system browser. Disable unnecessary permissions, popups, remote debugging in release, and unsolicited downloads. Never disable browser sandboxing or TLS verification to make a test pass.

## 3. Local key protection

Implement an explicit lock boundary in Rust. UI lock screens alone cannot block native decryption calls. Unlock returns an opaque vault capability/session, not key bytes. Sensitive commands check that capability and current lock generation. Lock invalidates handles, cancels key-dependent tasks, closes sensitive previews, and clears reachable plaintext buffers as practical.

Store device vault and session credentials using the selected OS-protected wrapper. Validate actual Windows Hello key gating in P01. If the available integration only prompts for user verification while the secret remains decryptable without it, label it accordingly and retain a stronger phrase-based mode; do not claim hardware-gated protection.

Use OS session-lock/suspend events. Prevent logging secret Rust values through Debug formatting. Review crash dumps, temporary export files, SQLite WAL, and process memory limitations. Clipboard copying is explicit; offer best-effort timed clearing only when clipboard content still matches what the app wrote.

## 4. Windows file integration

Drag-and-drop enters through native selection validation. Native file handles and export destinations are opaque to the frontend. Chunk streaming is native, bounded, cancellable, and resumable. Avoid passing base64 gigabytes across IPC. Return progress counters and small metadata only.

Choose a constrained mechanism for previews that need decrypted bytes. Any local protocol/stream route must use unpredictable short-lived capabilities, strict scope, and no arbitrary path mapping. An external PDF viewer is an explicit plaintext export, not an encrypted in-app preview.

## 5. Windows updates

Build installers reproducibly where feasible and generate SBOM/dependency manifests. Sign Windows artifacts with appropriate OS code-signing credentials when available, and separately verify Tauri updater signatures. Tauri update-signature verification must remain enabled [SRC-15]. Never ship private updater keys with the app or on the runtime API host.

Update metadata must enforce expected platform/channel/version, resist unintentional downgrade, and fail closed on invalid signatures. Stage local migrations so a failed update does not destroy encrypted data or outbox state. Provide a recovery installation path. An unavailable signing certificate is a release artifact limitation, not permission to label an unsigned build production-signed.

## 6. PWA architecture

Manifest includes stable id, name, icons, start_url, scope, display mode, theme, and install instructions. Service worker caches only approved static application resources and explicitly managed ciphertext where appropriate. Never cache authentication responses, recovery input, plaintext exports, or decrypted document responses. Do not let broad runtime-cache rules capture arbitrary API traffic.

IndexedDB supports small transactional encrypted records/outbox. OPFS is the preferred encrypted chunk cache after feature testing. Crypto and file processing run in a worker. Separate accounts have separate encrypted stores; signing out must not expose another account's cached state.

Use no third-party remotely loaded scripts, fonts, trackers, analytics, preview services, or cryptographic modules. Bundle exact dependency versions. Strict CSP must support the actual deployment and prevent arbitrary script execution without claiming to defeat a compromised delivery origin.

## 7. PWA lifecycle and storage

An iPhone may stop background work, reclaim memory, evict origin data, or discard selected file access. Persist meaningful progress before these events. Do not rely on Background Sync, Web Push, or a wake lock as a guarantee of long-running transfer completion.

On hide/background: mask the sensitive UI promptly, save encrypted state, and lock for resumed access by default. Snapshot/screenshot protection cannot be guaranteed for PWA. On resume: recheck session, local-vault state, server cursor, memberships, and transfer acknowledgements before continuing.

Storage APIs provide estimates, not guaranteed capacity. Request persistent mode, handle denied requests and storage exhaustion, expose cache use, and recover from an empty/recreated origin store through normal enrollment/recovery [SRC-12, SRC-13]. Never store the only recovery secret in PWA storage.

## 8. Passkeys and PRF matrix

Test ordinary WebAuthn separately from PRF. Record iOS release, browser/PWA mode, authenticator/provider, passkey type, registration/lookup behavior, PRF enabled/results, user verification, and recovery behavior. A synced passkey does not automatically transfer the application's independently generated device identity.

Offer PRF unlock only when verified for that credential. Adding a new passkey requires existing unlocked access to create its local key wrapper; registering a passkey on the server cannot regenerate an unknown content secret. Keep a strong phrase/recovery fallback and explain that cloud-synced passkey security depends on the selected provider's account protection.

## 9. Notifications

Request permission only after a user action and explain the benefit. Use neutral text such as “New activity in your vault.” No decrypted titles/body/filenames in push payloads, URLs, badges, or notification actions. A push hint may identify opaque scopes but must be authorized on opening. Never provide a group decryption key to a service worker solely to show message previews while locked.

WebKit supports Web Push for installed Home Screen apps, but push is not an invitation for silent indefinite background execution [SRC-14]. Notifications are optional; their absence must not prevent sync.

## 10. P01 feasibility deliverable

Before a large UI build, prototype with synthetic content and record:

- Native/browser encryption interoperability and actual memory usage.
- Windows local key wrapper and real Hello behavior.
- PWA login and local unlock, with and without PRF.
- Reading/encrypting/uploading a 1 GB source incrementally.
- Resume after network loss, force-close, lock/background, and source reselect.
- Download/decrypt/save a 1 GB file into iOS Files with bounded memory.
- Storage exhaustion, persistent-mode denial, and clean re-enrollment after storage deletion.
- PWA update while unsynced work exists; no cache/schema-induced data loss.

Desktop Playwright WebKit or an iOS simulator is useful but not proof of real iPhone storage, memory, passkey-provider, or Files export behavior. Record exact physical devices and evidence. If unavailable, leave this gate unverified while continuing independent work.

## 11. Origin, multi-window and lifecycle details

Use file 02's same-site, cross-origin deployment consistently. Static PWA app origin and API origin have separate deploy/write credentials. CSP script-src/worker-src must permit only the bundled application sources and explicitly required local worker mechanism; the API origin is connect-src only. Do not add the API to script-src, host API-generated JavaScript under the app origin, or allow arbitrary redirects to script resources. Explicit frame-src/frame-ancestors/object-src/base-uri/form-action rules and a tested Permissions-Policy are required. Configure CORS only for the exact application origin, credentials where needed, Vary: Origin, and bounded preflight methods/headers. Never reflect an arbitrary Origin or assume SameSite replaces CSRF [SRC-05, SRC-20].

Different accounts use independent vault namespaces and lock generations. Within one account profile, multiple windows/tabs coordinate a single sync/outbox writer using a transactional lease and fencing value. Web Locks may optimize supported browsers but are not the only correctness mechanism. A crashed leader can be replaced without duplicating publication or nonce state.

Passkey prompts, file pickers and system share/save sheets may hide the PWA. Capture nonsecret operation state and durable encrypted work before opening them. Background masking/locking still applies; results arriving under an old lock generation cannot decrypt or publish. Resume asks for unlock and safely restarts/continues the intended operation without an endless unlock->prompt->lock loop. A plaintext export already handed to the operating system cannot be remotely withdrawn; show that boundary before handoff.

Verify browser fetches include credentials for the intended API origin only; frontend HTTP wrappers reject arbitrary user-supplied base URLs. Native code uses its own bearer flow, never copies a PWA cookie jar into WebView2. API errors and push messages are data, never executable update instructions.
