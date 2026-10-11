# AnyNote

An invite-only, end-to-end encrypted notes and files service for Windows
(Tauri 2 / WebView2) and iPhone (installed PWA), backed by Laravel, MariaDB,
Nginx and PHP-FPM.

**Current state:** P00, P02 protocol design and P03 development foundation are
complete. P01 has scoped Windows/iPhone and host feasibility evidence; its full
physical matrix remains open. Initial OpenAPI, generated types, strict common
errors and content-free logs are verified against synthetic services. Product
authorization, storage, crypto adapters and deployment follow P04 onward.
Qualified independent review and production release gates remain open. Do not
store real secrets or user data in experimental builds.

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

No release license has been chosen for AnyNote. Third-party component licenses
do not grant a license to this project's own source or the supplied specification.

P01 experiment: [commands and boundaries](experiments/p01/README.md).
Physical trials: [owner actions and required results](docs/P01_OWNER_TRIALS.md).
Backend foundation: [commands and boundaries](docs/P03_DEVELOPMENT.md).

P04 backend foundation is verified: scoped current SQL authorization,
immutable revisions, atomic quota/receipt/event transactions and supervised
maintenance. See [P04 backend guide](docs/P04_BACKEND.md) and
[validation evidence](docs/TEST_EVIDENCE.md). Full user operations continue in P05 onward.
