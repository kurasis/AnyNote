# System Architecture

## 1. Components

| Component | Responsibilities | Must not do |
| --- | --- | --- |
| React/TypeScript UI | Navigation, editing, accessibility, user decisions | Hold Windows long-lived private keys or unrestricted native capabilities |
| Rust Windows core | Key custody, crypto, encrypted persistence, transfers, filesystem export, API sessions | Execute remote application code or arbitrary frontend shell commands |
| PWA crypto worker | Client encryption, signatures, key unwrap, chunk processing | Send keys or plaintext to API, logs, analytics, or crash collectors |
| PWA IndexedDB/OPFS | Ciphertext, encrypted outbox, cached protocol state, local wrappers | Persist unlocked private keys or a plaintext search database |
| Laravel API | Authentication, ACLs, signed-event validation, synchronization, quotas, upload orchestration | Decrypt content, generate content keys, OCR files, or create content previews |
| MariaDB | Metadata, immutable ciphertext revisions, security events, quotas | Store plaintext titles/body/filenames/search text |
| Private blob store | Immutable encrypted chunks and encrypted derived attachments | Use user filenames as physical paths |
| Nginx | TLS, static assets, constrained routing, authorized ciphertext delivery | Expose private upload directories directly |
| Queue/scheduler | Cleanup, notification hints, maintenance, backup coordination | Depend on decrypted content |

## 2. Deployment shape

Start with a modular Laravel monolith, one MariaDB deployment, and a private filesystem blob store on a single application host. Run queue workers and scheduler as supervised services. A database-backed queue is sufficient initially. Redis and an S3-compatible object store are optional future adapters, not mandatory dependencies.

Serve the static PWA at an isolated origin, for example https://app.vault.example, and the API at https://api.vault.example (illustrative reserved names). Use separate serving/deployment permissions; PHP-FPM cannot modify or serve application-origin routes. Do not proxy arbitrary PHP responses under that origin: a broad script-src 'self' could make a compromised API path an executable script source. The API origin is allowed by connect-src only, not script-src, worker-src, or frame-src. Shared-host root, DNS/TLS, and static-release compromise remain outside this API-only isolation claim.

Use credentialed cross-origin fetch, exact CORS, host-only API session cookies, and file 05's explicit CSRF bootstrap. Do not broaden cookie Domain to the parent domain to make an XSRF cookie readable. WebAuthn ceremonies and native-browser login/consent run on the static app origin; configure RP ID app.vault.example and exactly that HTTPS origin. API endpoints issue/verify challenges but never derive trusted origins from untrusted headers. A same-origin variant requires a separate ADR and cannot inherit the stronger isolation claim.

Use separate administrative access through VPN/private network or tightly restricted operator access. Production database and internal storage endpoints are not public. No phpMyAdmin or development debug toolbar on the public service.

## 3. Reference code organization

Recommended monorepo areas:

- apps/web: React application and PWA shell.
- apps/desktop: Tauri host, Rust integration, capabilities, packaging.
- apps/api: Laravel application, migrations, policies, queues.
- packages/contracts: versioned JSON schemas, generated TS types, OpenAPI inputs.
- packages/protocol: canonicalization, typed protocol operations, public verification.
- packages/ui: shared components and presentation logic.
- packages/platform: interface definitions for crypto, storage, files, session, notifications.
- crates/vault-core: native cryptographic and persistence implementation.
- fixtures/protocol: public deterministic vectors and adversarial test cases.
- tests/integration and tests/platform: cross-component and real-platform procedures.
- infra: reviewed deployment configuration and local synthetic environment.
- docs: implementation ADRs, protocol freeze, progress, operations, and evidence.

This is an organizational recommendation, not permission to create unsupported dependencies. Avoid duplicating business rules between browser and native implementations. Share schemas and test vectors even where cryptographic adapters necessarily differ.

## 4. Platform boundary

Define narrow adapters: CryptoProvider, LocalStore, TransferStore, FileSource, ExportSink, SessionProvider, DeviceKeyStore, LockController, NotificationProvider. Methods must carry typed IDs and constrained intents, not arbitrary paths, URLs, SQL, JavaScript, or shell strings.

Windows operations such as reading a selected file use opaque handles created by native selection; a frontend cannot simply request any path. API base origins and download routes are configured and validated in native code. PWA performs cryptographic work in a worker for responsiveness; a worker is not a security boundary against malicious same-origin scripts.

Use a mature libsodium binding on Windows and a compatible maintained browser/WASM distribution for PWA, subject to the feasibility phase. If a shared Rust/WASM core is demonstrably supportable it may be selected by ADR, but custom primitive implementations are prohibited. Native and browser output must pass the same fixtures.

## 5. Flows

### Entry write

UI edit -> encrypted local revision/outbox transaction -> client signature -> authorized API commit -> MariaDB immutable revision + sync event transaction -> acknowledgement -> clear pending state. The server can inspect public envelope headers but cannot read the entry.

### File write

Selected source -> reserve quota/upload session -> chunk encryption/upload -> signed encrypted manifest -> committed unattached file version -> separately signed entry revision referencing it. File commit and attachment publication are distinct states. A crash between them leaves a recoverable unattached file; file 10 defines its publication journal and cleanup.

### Read

Fetch only authorized metadata/ciphertext -> validate membership/device chains and object signatures -> unwrap relevant key -> decrypt -> validate decrypted schema -> render through safe renderer. Cache ciphertext, not accidental plaintext.

### Live updates

v1 uses cursor-based delta polling while visible, with backoff. Push is only a generic hint. WebSockets/SSE can be added as a hint transport, but a dropped hint must never lose data; the delta API remains authoritative for transport delivery.

## 6. Compatibility and versioning

Version API, wire protocol, encrypted payload schema, key-container schema, file format, and local DB schema independently. An unknown cryptographic version fails closed; it is not interpreted using legacy defaults. A client that cannot write the current protocol may still offer a verified read-only mode if explicitly supported.

Migration of encrypted content happens on an authorized client. Laravel cannot migrate plaintext note structure inside a ciphertext. Use lazy, resumable client migrations with old data retained until new data verifies. Immutable ciphertext revisions and published chunks are never rewritten in place.

## 7. Scope and scaling

Design for 10 accounts, 50 active devices, 100 GB committed encrypted data, up to 100,000 retained entry revisions in a performance fixture, and modest concurrent use. These are sizing fixtures, not promises about every server configuration. Paginate and index all unbounded lists. Do not implement microservices, Kubernetes, global deduplication, or distributed consensus to meet this scope.

Select maintained versions in phase P00. Laravel 13 is the current reference major at preparation time; exact PHP, MariaDB LTS, Node LTS, Rust, Tauri, and WebView2 versions must be recorded in the compatibility matrix and lockfiles. Current support policy must be checked again when development starts [SRC-01, SRC-02].
