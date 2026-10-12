# Development setup

## P00 baseline (available now)

Use Git and Python 3.12+ (validated on Git 2.52.0 / Python 3.12.14). Clone the
repository or use the existing isolated cloud checkout; no worktree is needed.

```sh
git clone https://github.com/kurasis/AnyNote.git
cd AnyNote
python3 scripts/check_baseline.py
```

In this cloud machine the working directory is `/workspace/AnyNote`; run the
same Python command there. No packages, credentials, servers or `.env` are
needed for baseline verification. The command validates specification hashes,
local document links, tracking records and exact size/framing arithmetic. It
does not validate encryption, platform compatibility or the future application.

## Application tooling foundation

Exact selected versions and primary sources are in [decisions](DECISIONS.md).
The isolated [P01 experiment](../experiments/p01/README.md) has working Rust/Node
setup, lockfiles, build/test commands and hosted Chromium checks now. P03 adds
apps/api, frozen Composer dependencies and a disposable container stack; see
[foundation setup](P03_DEVELOPMENT.md). Artisan runs in the PHP container, not
a host PHP installation. Use npm with
`npm ci`, Cargo with `--locked`, and Composer installation from `composer.lock`
once those files exist. Future installs must keep artifact checksums,
package-signature and TLS verification enabled.

Backend development will need PHP CLI/FPM extensions including sodium,
pdo_mysql, mbstring, intl, openssl, fileinfo, DOM/XML and tokenizer, Composer,
MariaDB and Nginx are now prepared for development. Queue/scheduler processes,
account flows and private blob adapters follow their product contracts; none are
initialized by the foundation check. Redis/S3 remain optional.

Windows builds need a Windows MSVC Rust toolchain, Microsoft C++ Build Tools
with Windows SDK, and WebView2. Linux compilation cannot prove DPAPI, Hello,
installer, suspend or WebView2 behavior. PWA feasibility needs actual installed
Safari PWA testing on physical iPhones, including the exact 1 GB export path.

## Network and credentials

Git HTTPS proxy access works. Package-manager presets currently cover GitHub
Git, raw GitHub, npm, crates, Rust, Node and Debian packages. Some primary
documentation hosts returned proxy HTTP 403. GitHub API now works, including
PRs and Actions evidence. Official
GitHub source mirrors were used where available; provenance is recorded.

The initial GitHub CLI auth/status failure preceded restored API access.
Existing injected authentication now supports Git, PRs and Actions; do not
extract credentials or request duplicate tokens. Record exact run/head evidence;
a pushed workflow alone is not evidence of a passed Actions run.

Future environment settings may need these **additional** destinations:
`laravel.com`, `www.php.net`, `mariadb.org`, `nginx.org`,
`v2.tauri.app`, `getcomposer.org`, `learn.microsoft.com`, `webkit.org`,
`doc.libsodium.org`. Preserve existing network presets and custom rules.

No production credentials or signing secrets are required by P00. Windows code
signing/updater credentials, hosting and independent reviewer availability are
later gates. Never enter secret values in chat or committed setup files.

## Complete P02/P03 contract checks

P02 design and P03 tooling are verified; product phases and qualified review stay
open. Follow [P03 commands and boundaries](P03_DEVELOPMENT.md) to install frozen
protocol/client dependencies and run `bash scripts/p03-checks.sh`. The command
checks strict types, actual schema drift, safe errors/logs and owned SQL/HTTP
integration. Generation is an explicit reviewed development action only; setup
and CI compare existing outputs. Preserve all prior schema/vector/lock bytes.

P04 targeted checks: `source scripts/runtime-env.sh && python3 scripts/p04-checks.py`.
This resets only the separately marked disposable `anynote_p04_tests` database,
runs real MariaDB authorization/concurrency/rollback checks and scoped maintenance
containers, then stops those maintenance services. Product migrations are never
automatically run by setup. See P04_BACKEND.md for public-signature native/browser
commands, schema bounds, saved-startup and phase limitations.

P05 full client core: `packages/crypto-core` and
`packages/protocol/adapters/core.mjs`. See [P05_CRYPTO_CORE.md](P05_CRYPTO_CORE.md)
for strict byte APIs, maintained dependencies, caller authority and worker/key
ownership. Frozen installation builds the new crate with `--locked`, verifies
its inventory and portable codec equivalence, and runs the actual native/Node
corpus. The optional cloud sandbox block remains explicit; GitHub CI requires
real sandboxed Worker, PHP public-only and Windows/MSVC acceptance. General PHP
payload JCS, local persistent vault and product auth routes are not added here.

## P06 authentication development

Read [P06_AUTHENTICATION.md](P06_AUTHENTICATION.md). Activate pinned runtimes,
then `python3 scripts/p06-stack.py up` and `check` start/verify owned TLS static/API
services and encrypted SQL sessions without replacing existing owned data. The
native adapter has its own frozen Cargo lock/inventory. Setup and generators
remain read-only. Full attack tests explicitly reset only the separately marked
synthetic P06 database; run them sequentially with P03 outage tests because both
use the owned MariaDB service. Strict-CSP browser and Windows gates run in CI.
No production credentials, migrations, deployment or device trial are involved.


## P07 encrypted local custody development

Read [P07_LOCAL_VAULT.md](P07_LOCAL_VAULT.md). Activate pinned runtimes; build/test
`packages/vault-native` with `--locked --all-features`, check formatting/clippy,
then run `python3 scripts/p07-native-inventory.py` and `python3 scripts/check-p07.py`.
The latter verifies exact frozen dependency/provider provenance and executes the
five Node custody suites. Ordinary `p06-stack.py up/check` preserves owned data.
Actual HTTP/browser attack acceptance explicitly resets only the marked P06
synthetic database; run sequentially with P03 outage checks. CI requires sandboxed
Chromium, verified TLS/strict CSP and Windows/MSVC with the independently measured
ABI reference. Static vault shell: `/auth/vault.html`; no general native key/token
IPC or production issuer is exposed. Saved P07 setup revision 15 does not by
itself publish a snapshot or prove fresh-task restoration.

## P08 trusted devices development

Read [P08_TRUSTED_DEVICES.md](P08_TRUSTED_DEVICES.md). Install the separate QR project
with `npm --prefix apps/devices-web ci --ignore-scripts` using the workspace cache,
activate runtime-env.sh, and run `python3 scripts/check-p08.py`: generated contracts
are compared read-only, four exact QR SRI/license records checked, seven workflow
suites and sixteen dense QR round trips executed. Native all-feature tests require
`--test-threads=1`, respecting the bounded process-wide Argon admission gate.

Ordinary p06-stack.py up/check preserves owned data and applies additive schema only
after owner-marker validation. Upgrade/attack tests explicitly use the marked
synthetic P06 DB; run sequentially with P03 outages. Mandatory trusted-devices.yml
verifies actual HTTP/SQL/native interop, sandboxed verified-TLS/strict-CSP UI and
Windows/MSVC/official-header ABI. Archive only public clean-source receipts, never
kit/QR/private fixture values. UI: `/auth/devices.html`. Draft save does not publish
or establish fresh restoration, authorize production deployment or owner trials.
