# P03 development foundation

This slice prepares a Laravel scaffold and real MariaDB/FPM/Nginx integration.
Product API, authentication, crypto and deployment are not implemented. P01/G1
and P02 remain open; authoritative contracts/generated types follow P02.

## Layout and reproduction

apps/api contains Laravel and frozen Composer dependencies; infra/dev contains
digest-pinned images and owned Compose services. scripts/dev-stack.py provides
install/up/check/test/stop. experiments/p01 remains independently runnable.
apps/web/desktop and crates/vault-core remain reserved architecture areas.
packages/contracts/protocol now contain isolated P02 candidate schemas/reference,
not product crypto or authorization. After owned install/up, run
python3 scripts/check-p02-crypto.py for independent public-fixture PHP HKDF/
signature/sealed-box/AEAD verification; its read-only reference mount does not
add an API route or general PHP JCS/parser implementation.

Tested on Linux x86_64 / Debian 13.6, Docker 28.4.0, Compose 2.40.3 and Python
3.12.14. Use a non-root developer UID. No host PHP/system service installation,
real account, external database or signing secret is required. From the existing
checkout (or a fresh clone):

```sh
source scripts/runtime-env.sh
python3 scripts/check_baseline.py
python3 scripts/install-p03-tools.py
python3 scripts/api-inventory.py
python3 scripts/check-secrets.py
python3 scripts/dev-stack.py install
python3 scripts/dev-stack.py up
python3 scripts/dev-stack.py test
```

install never resolves dependency versions or changes the committed lock and
never migrates the database. up/check verify an actual HTTP database request,
not just a listening port. test checks native PHP extensions, strict Composer
validation/platform requirements/advisories, Pint, PHPUnit, temporary commit/
rollback/cleanup, path/host/static isolation, actual bindings/users and DB outage
503/restart. Advisory status is time-dependent and is not a security audit.

artifacts/p03/foundation-report.json records actual versions, source commit/dirty
flag and source-input SHA-256 receipts. Use the current run's artifact; a stale
local report is not a new PASS. CI repeats installation/integration from a fresh
checkout and preserves content-free evidence. Stop only the owned project:

```sh
python3 scripts/dev-stack.py stop
```

stop preserves its disposable DB volume. Never globally prune Docker resources,
migrate production data or remove another project. Do not delete .local/p03 while
retaining its DB volume: generated credentials must remain consistent. Resetting
the synthetic volume is a separate explicit action. Live processes do not survive
environment snapshots; run up/check after restoration.

## Isolation and state

Nginx alone binds 127.0.0.1:18080. Set ANYNOTE_DEV_PORT before first initialization
of another disposable checkout; it then persists. Project names derive from
checkout paths. MariaDB/FPM publish no host ports; the DB network is internal.
api.anynote.test routes only to the fixed PHP front controller; app.anynote.test
serves a read-only static placeholder. PHP does not mount/write that static area.
Use a Host header for local tests; no DNS, TLS or phone deployment is provisioned.
Unknown hosts/private paths/arbitrary PHP files are denied. FPM/Nginx run under
the developer UID with dropped capabilities and no new privileges.

Readiness is read-only and uncached, with only ready/unavailable JSON and a
generic DB-outage 503. It and foundation:check refuse production environment.
No product account/session route, default auth model or persistent schema exists.
The command uses one connection-local TEMPORARY InnoDB table with numeric
synthetic values, commits, rolls back and drops it. APP_KEY is a disposable
Laravel runtime key, never an E2EE/recovery key.

.local/p03 stores an ownership marker and mode-0600 generated synthetic passwords/
APP_KEY; it is ignored and excluded from evidence/CI uploads. The nonsecret .env
example is copied only when absent; existing local files are preserved. Nginx
access/error logs, PHP error display and Laravel content logging are disabled in
this stack. CLI test diagnostics remain visible without exception arguments.
Future request IDs/structured errors/logging follow the P02 contract.

Cloud builds reuse injected proxies and the platform's public CODEX_PROXY_CERT
trust anchor through an ignored local build copy. Docker builder state uses an
owned writable DOCKER_CONFIG default. Debian signed metadata/package hashes and
HTTPS verification remain enabled; no credential extraction, host-wide trust
change or verification bypass. Never dump full Compose/container environment.
CI without that proxy uses standard image trust.

## Pins and scanning

infra/dev/versions.json preserves exact image manifest digests/primary sources;
Composer lock and its generated inventory preserve exact packages/licenses/
source references. Signed Debian compiler-library pins are explicit, but indirect
OS packages remain repository-resolved: no byte-identical image rebuild or release
SBOM is claimed. Missing/security-updated pins require review.

Gitleaks 8.30.1 has a checksum-verified official installer. Scan all Git-visible
source, including new files, excluding ignored state/vendor. A rule-scoped AND
allowlist covers only SHA-256 lines in passkeylocal/PROVENANCE.json and generated
foundation source-input receipts. Three disposable fake PATs must be rejected,
including both allowlisted paths; output is
redacted. This scans the current source tree, not all Git history or every possible
credential format. Upstream skeleton provenance is apps/api/UPSTREAM.md. The
Composer proprietary marker expresses no selected redistribution grant; the
future AnyNote release license remains unselected and upstream licenses unchanged.

Rollback: revert the foundation addition and stop its own synthetic project.
No production format/migration or P01 reference/device-kit changes occur.

## P02 candidate contract checks

The separate packages/protocol reference harness adds strict candidate schemas
and serialization vectors only, not product OpenAPI/auth/server acceptance.
Read protocol-v1.md. Frozen install: `npm --prefix packages/protocol ci
--ignore-scripts --cache /workspace/.cache/npm --no-audit --no-fund`. Run
`npm --prefix packages/protocol test`, `npm --prefix packages/protocol run
fixtures:check`, `npm --prefix packages/protocol run inventory:check`, and
`python3 scripts/check-p02-fixtures.py`. The dedicated pinned Actions workflow
protocol-candidate.yml repeats these checks/advisory audit. Existing foundation
source scan now tests changed fixture-shaped values as well as fake PAT paths.
Candidate consistency success never authorizes a product write or historical
record. Full generated types/OpenAPI/errors/logging remain later P03 work.
