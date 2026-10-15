# AnyNote

An invite-only, end-to-end encrypted notes and files service for Windows
(Tauri 2 / WebView2) and iPhone (installed PWA), backed by Laravel, MariaDB,
Nginx and PHP-FPM.

**Current state:** P00 and P02–P14 are software verified. P14 adds the native Windows client,
single installer and actual WebView2/dialog/gigabyte/update/restart acceptance.
P13 adds protected search,
safe previews/thumbnails, reference-safe retention and independent portable recovery.
P10 adds shared roles, full-history
invitations, signed membership, revocation/rekey and owner transfer. P09 includes private
groups, encrypted notes/preferences, safe Markdown/checklists, protected local
and server saving, conflicts and cross-device flows. P08 includes independently
pinned enrollment, signed rosters, cascading revoke and root-signed recovery.
P01 has scoped Windows/iPhone feasibility evidence; its full physical matrix is
open. The next phase is P15 iPhone PWA completion. Qualified
independent review and production release gates remain open. Do not store real
secrets or user data in experimental builds.

## Start here

1. Read [the supplied specification](docs/spec/00_README.md).
2. Read [progress](docs/PROGRESS.md) and [the next task](docs/NEXT_TASK.md).
3. Follow [development setup](docs/DEVELOPMENT.md).
4. Run `python3 scripts/check_baseline.py` from the repository root.

This baseline check needs Python 3.12+, uses only the standard library, and
does not install dependencies or start servers. CI runs the same check.

The original 21 specification documents and checksum manifest are preserved in
`docs/spec`. Their instructions define implementation requirements; progress
and test evidence describe work actually performed. The supplied archive was
named `encrypted_notes_files_spec_en_v1.zip`; its contents identify the reviewed
specification as **1.1.0**, superseding 1.0.0.

## Implementation records

- [Repository assessment](docs/REPOSITORY_ASSESSMENT.md)
- [Decisions and version matrix](docs/DECISIONS.md)
- [Requirements checklist](docs/REQUIREMENTS.md)
- [Dependency and license inventory](docs/DEPENDENCIES.md)
- [Risks](docs/RISK_REGISTER.md)
- [Known limitations](docs/KNOWN_LIMITATIONS.md)
- [Test evidence](docs/TEST_EVIDENCE.md)

Developer documentation, source and identifiers are in English. Chat with the
owner is in Russian. The eventual interface must include English and Russian.

The native Windows development candidate is scoped GPL-3.0-only and bundles
its license, notices and exact corresponding-source commit. No whole-project
release license has been chosen for the other AnyNote components or supplied
specification; third-party licenses do not license that separate source.

P01 experiment: [commands and boundaries](experiments/p01/README.md).
Physical trials: [owner actions and required results](docs/P01_OWNER_TRIALS.md).
Backend foundation: [commands and boundaries](docs/P03_DEVELOPMENT.md).

P04 backend foundation is verified: scoped current SQL authorization,
immutable revisions, atomic quota/receipt/event transactions and supervised
maintenance. See [P04 backend guide](docs/P04_BACKEND.md) and
[validation evidence](docs/TEST_EVIDENCE.md). Full content workflows remain owned by later phases.

Client cryptographic core: [P05 guide and boundaries](docs/P05_CRYPTO_CORE.md).
Account authentication: [P06 API, UI, native adapter and commands](docs/P06_AUTHENTICATION.md).
Encrypted local custody: [P07 vault, locking and boundaries](docs/P07_LOCAL_VAULT.md).
Trusted devices and recovery: [P08 workflows and boundaries](docs/P08_TRUSTED_DEVICES.md).

Private notes: [P09 vault, protected publication and commands](docs/P09_PRIVATE_NOTES.md).

Shared groups: [P10 roles, signed membership and maintenance](docs/P10_SHARED_GROUPS.md). P10 software acceptance is recorded in PROGRESS and TEST_EVIDENCE.

Synchronization and offline durability: [P11 implementation and evidence](docs/P11_SYNC.md).

Encrypted files, recovery and quota lifecycle: [P12 implementation and evidence](docs/P12_FILES.md).

Protected content and independent recovery: [P13 guide](docs/P13_CONTENT.md) and
[exact-source acceptance](docs/evidence/p13/README.md).

Windows application: [operator/build guide](docs/P14_WINDOWS.md),
[update signing contract](docs/P14_UPDATE_SIGNING.md) and
[exact-source software acceptance](docs/evidence/p14/README.md).
