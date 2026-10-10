# Decisions

## ADR-001 — Scope, stack and initial version matrix

Date: 2026-10-10. Status: ACCEPTED for development baseline; platform support
remains a candidate until P01 evidence. Wire contracts are not frozen by this ADR.

### Context and options

The repository is empty. Specification 1.1.0 requires Tauri/Rust/React/WebView2,
an iOS PWA, and Laravel/MariaDB/Nginx/PHP-FPM. Preserve this stack instead of
substituting a Node backend, Electron or native iOS. Use npm initially to avoid
an additional package-manager bootstrap; PHP and Rust retain Composer/Cargo.

### Selected exact development versions

| Component | Selected version | Source / support evidence | Runtime state |
| --- | --- | --- | --- |
| Python baseline checker | 3.12.14 | Installed runtime; CI pins same version | Executed |
| Git | 2.52.0 observed | Installed runtime; no special Git feature required | Executed |
| Node | 24.21.0 LTS | Official release index and Release schedule; 24.x security support to 2028-04-30 | Host has 24.19.0; install target at P03 |
| npm | 11.9.0 baseline candidate | Installed with current Node; confirm/pin chosen Node distribution's npm at P03 | Available, no dependency install yet |
| Rust | 1.99.0 | Official stable channel dated 2026-10-01 | Not installed |
| Tauri Rust / JS API | 2.12.2 | crates.io and official npm package metadata | Not installed |
| React | 19.3.0 | Official npm package latest metadata | Not installed |
| TypeScript | 7.0.2 | Official npm package latest metadata; verify build-tool integration at P03 | Not installed |
| Laravel framework | 13.35.0 | Packagist plus official Git tag; Laravel 13 supports PHP 8.3–8.5, security through 2028-03-17 | Not installed |
| PHP CLI / FPM | 8.4.24-1~deb13u1 | Debian trixie package baseline; PHP 8.4 active support to 2026-11-21, security to 2028-11-21 | Not installed |
| Composer | 2.8.8-1+deb13u3 | Debian trixie package baseline; Composer 2 runtime API | Not installed |
| MariaDB | 11.8.6 (Debian 1:11.8.6-0+deb13u1) | Debian trixie maintained package; upstream release tag verified | Not installed |
| Nginx | 1.26.3-3+deb13u7 | Debian maintained security revision; upstream tag verified | Not installed |
| Browser sodium candidate | libsodium-wrappers-sumo 0.8.4 | Official npm metadata; binding must pass P01 before acceptance | Not installed |

Versions are assessment pins, not an application lockfile or claim of tested
integration. Before P03 installation resolve current security fixes, pin the
actual binaries/packages and transitive dependencies, and record justified
changes here. Debian package revisions use distribution maintenance rather than
an assumption that an older upstream Nginx minor is supported upstream. Native
sodium binding, canonicalization, WebAuthn and OAuth libraries await P01/P02;
do not choose them implicitly or write custom primitives.

### Supported OS candidates

| Platform | Candidate | Acceptance still needed |
| --- | --- | --- |
| Windows | Windows 11 24H2 or later, x64, current Evergreen WebView2 | Physical target/version capture; actual Hello/CNG key gating, DPAPI limits, file lifecycle |
| iPhone | iOS 18.x minimum candidate and current shipping iOS; installed PWA | Physical device/provider exact versions, 1 GB export/resume, PRF, OPFS, eviction, lifecycle |
| Server development | Debian 13 x64 | P03 actual Laravel/MariaDB/Nginx/PHP-FPM startup and integration |

These are test targets, not advertised supported platforms. Record exact OS,
WebView2/Safari, SDK/compiler/provider versions in P01 measured evidence.

### Scope and consequences

Freeze invite-only independent accounts, private/shared groups, threads,
versioned entries/checklists/attachments, owner/editor/reader, E2EE for titles,
bodies, filenames, tags, drafts, previews and retained versions. Keep routing,
authorization, length and accounting metadata visible. Limits are decimal
1,000,000,000 bytes/file and 100,000,000,000 committed encrypted bytes globally.

No universal server recovery key. Authentication, trusted devices and local
unlock are separate. Recovery requires an offline user-held kit. Concurrent
edits and revocation preserve unsynced work. Static app and API origins are
separate, with exact CORS, host-only API cookies and synchronizer CSRF.

No continuous iOS background-transfer guarantee, universal rollback/fork
detection, remote erasure, forward secrecy or immunity to a malicious PWA origin.
English/Russian interface localization is required; repository artifacts use
English. OCR, AI, federation, public signup and server previews remain deferred.

Security effects: preserve the specified endpoint/server trust boundaries and
all independent-review gates. Migration effects: none; no data or schema exists.
Tests: baseline artifact verification only at P00; native/browser/backend
interoperation and physical platform compatibility are assigned to later phases.

### Primary sources checked

- [Laravel release policy source](https://raw.githubusercontent.com/laravel/docs/13.x/releases.md)
- [Laravel framework package metadata](https://repo.packagist.org/p2/laravel/framework.json)
- [Node release index](https://nodejs.org/dist/index.json) and [support schedule](https://raw.githubusercontent.com/nodejs/Release/main/schedule.json)
- [Rust stable channel](https://static.rust-lang.org/dist/channel-rust-stable.toml)
- [Tauri crate](https://crates.io/api/v1/crates/tauri) and [official prerequisites source](https://raw.githubusercontent.com/tauri-apps/tauri-docs/v2/src/content/docs/start/prerequisites.mdx)
- [Tauri API](https://registry.npmjs.org/@tauri-apps/api/latest), [React](https://registry.npmjs.org/react/latest), [TypeScript](https://registry.npmjs.org/typescript/latest), [sodium JS](https://registry.npmjs.org/libsodium-wrappers-sumo/latest)
- [PHP support policy source](https://raw.githubusercontent.com/php/web-php/master/include/branches.inc)
- [Debian trixie package index](https://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz)
- [MariaDB official source](https://github.com/MariaDB/server), [Nginx official source](https://github.com/nginx/nginx)

See `SOURCE_EVIDENCE.json` for fetched metadata hashes, selected observations and
Git tag SHAs. Direct documentation hosts were blocked; official source mirrors
were used. This is source research, not a dependency security audit.

## ADR-002 — P01 experimental bindings and runner

Date: 2026-10-10. Status: ACCEPTED for synthetic feasibility only.

Select maintained `libsodium-rs` 0.2.5 (official jedisct1 repository, Rust MSRV
1.88) with locked `libsodium-sys-stable` 1.24.0 and native libsodium 1.0.22.
Keep the default bundled signed sources; do not enable `fetch-latest` or replace
the upstream signature key. Select browser wrappers/core 0.8.4, which reports
libsodium 1.0.22, bundled with esbuild 0.28.2. Avoid the older sodiumoxide
binding and custom primitives. Cross-runtime tests are required before app use.

Rust 1.99.0 and Node 24.21.0 were installed with official artifact checksums.
The Node distribution includes npm **11.19.0**; this replaces ADR-001 npm 11.9.0
candidate. JS dependencies use exact versions, a core override, npm lockfile
and an explicit allowlist for the esbuild 0.28.2 install script.

Playwright Core 1.64.0 drives an actual host browser. Chromium keeps its sandbox
enabled. The cloud helper owner/user-namespace restrictions prevent startup;
hosted Ubuntu supplies a supported sandbox. Do not disable it or weaken the
container to fabricate browser success. Tests use local bundled sources only,
CSP with narrow WASM allowance and a loopback ciphertext-only test transport.

This selects no application canonicalization, authenticated pairing, key
wrapper or sender authorization. Sealed-box decryptability is not permission.
Physical Windows/iPhone and independent-review gates remain open. Migration:
none; this isolated experiment has only public fixtures and temporary data.

Primary metadata checked on this date: crates.io `libsodium-rs` /
`libsodium-sys-stable`, npm `libsodium-wrappers-sumo`, `playwright-core`, `esbuild`,
and the fetched official crate build source (Minisign verification retained).
Actual positive/negative results are tracked in TEST_EVIDENCE.md.
