# Repository assessment — P00

Observed 2026-10-10, before implementation.

P03 update (2026-10-11): apps/api now contains a minimal Laravel scaffold and
frozen Composer inventory. infra/dev and scripts/dev-stack.py prepare owned
loopback MariaDB/FPM/Nginx using Docker 28.4.0/Compose 2.40.3. No host PHP/system
service, product schema/account, application UI or production deployment is
installed. Original observations below remain historical.

## Existing repository

- Checkout: `/workspace/AnyNote`; origin `https://github.com/kurasis/AnyNote.git`.
- Local symbolic branch: `work`, unborn, no HEAD commit.
- `git ls-remote origin` succeeded with zero refs. `main` did not exist.
- No tracked files, application code, tests, manifests, lockfiles, instructions,
  CI, local modifications or user files existed in the checkout.
- Native Git HTTPS read access works. GitHub CLI authentication failed; this is
  separate from the platform's Git proxy and does not prove push access absent.
- Bootstrap will create the first commit and push it to `main`, without rewriting
  existing history. Future remote changes must be reconciled without force push.

## Cloud machine

| Observation | Value |
| --- | --- |
| Host | Debian GNU/Linux 13.6 (trixie), Linux x86_64 |
| Python | 3.12.14 |
| Git | 2.52.0 |
| Node / npm | 24.19.0 / 11.9.0 |
| Docker daemon | 28.4.0; `docker info` succeeded |
| CPU | 5 available processors |
| RAM / swap | Approximately 33 GiB / none |
| Workspace space | Approximately 30 GiB available |
| Rust / Cargo | Not on PATH |
| PHP / Composer | Not on PATH |
| MariaDB / Nginx | Not on PATH |

These are observations, not a prepared application runtime. P00 validation needs
only Python. P03 must install/pin the app toolchains, create lockfiles, run real
services and validate them. A 100 GB production capacity drill cannot run on
this workspace; it needs a separate appropriately sized synthetic host.

## Archive intake

Read `00_README.md` first, then the mandatory 01–06, 14, 19 and 20 chapters;
also read 15, 16 and 18 for P00 execution, limits and traceability. Extracted
only the 21 numbered Markdown documents and the checksum manifest into
`docs/spec`. Original document bytes are preserved.

Archive instructions are specification inputs. The owner's chat request supplies
the authorization to develop, automatically push/merge, and use GitHub Actions;
it does not turn every future deployment described in the archive into an
authorized live operation.

## Baseline commands

Before application development: `python3 scripts/check_baseline.py`.
No application build/start/test commands existed. Do not report the baseline
documentation checks as application tests.
