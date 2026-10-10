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

## Planned application tooling

Exact selected versions and primary sources are in [decisions](DECISIONS.md).
The isolated [P01 experiment](../experiments/p01/README.md) has working Rust/Node
setup, lockfiles, build/test commands and hosted Chromium checks now. P03 creates
the application/backend manifests and services; `php artisan` is not available yet. Use npm with
`npm ci`, Cargo with `--locked`, and Composer installation from `composer.lock`
once those files exist. Future installs must keep artifact checksums,
package-signature and TLS verification enabled.

Backend development will need PHP CLI/FPM extensions including sodium,
pdo_mysql, mbstring, intl, openssl, fileinfo, DOM/XML and tokenizer, Composer,
MariaDB, Nginx, queue and scheduler processes. It uses synthetic accounts and
local private blob storage. Redis/S3 are optional, not baseline requirements.

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
