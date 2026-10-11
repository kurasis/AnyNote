# Initial dependency and license inventory

P00 candidate inventory, checked 2026-10-10. No application dependency manifests,
transitive lockfiles or release artifacts existed at P00. P01 additions are
recorded below. This is not
a release SBOM. P03 must generate exact resolved inventories, notices and
automated dependency/secret checks; P17 reviews the release chain.

| Component | Version selection | License / obligation to confirm at packaging |
| --- | --- | --- |
| Node | 24.21.0 | MIT; bundled dependencies have additional notices |
| npm | 11.9.0 candidate | Artistic-2.0; pin actual installed npm at P03 |
| Rust | 1.99.0 | MIT OR Apache-2.0; compiler distribution notices |
| Tauri | 2.12.2 | MIT OR Apache-2.0 (official crate/npm metadata) |
| React | 19.3.0 | MIT (official npm metadata) |
| TypeScript | 7.0.2 | Apache-2.0 (official npm metadata) |
| Laravel | 13.35.0 | MIT (official Packagist metadata) |
| PHP | Debian 8.4.24 | PHP-3.01; bundled extension notices |
| Composer | Debian 2.8.8 | MIT; distribution notices |
| MariaDB server | Debian 11.8.6 | GPL-2.0; review redistribution/linked client dependencies |
| Nginx | Debian 1.26.3 | BSD-2-Clause; distribution patches/modules notices |
| libsodium-wrappers-sumo | 0.8.4 | ISC (npm metadata); bundled native/WASM library notices |
| libsodium native binding | Not selected | P01 evaluates maintained binding, license, library version and static linking |
| age export implementation | Not selected | P13 pins maintained implementation and its license |
| Python checker runtime | 3.12.14 | PSF-2.0; standard library only |
| checkout / setup-python CI actions | v5.0.0 / v6.0.0 exact Git SHAs | MIT; CI infrastructure only |

Non-registry license descriptions are preliminary upstream license families,
not a completed distribution compliance assessment. Capture exact LICENSE,
NOTICE and Debian copyright files for shipped versions before release.
Do not apply any third-party license to AnyNote automatically; the owner has
not selected a project license. The specification is owner-supplied input.

## P01 resolved experiment inventory

The isolated experiment now has Cargo/npm lockfiles and a machine-readable
inventory in experiments/p01/dependency-inventory.json: 70 Rust package records
(including the unlicensed private root) and 30 npm lock entries including
optional platform binaries. Licenses come from package metadata, not inference.
Rust 1.99.0, Node 24.21.0/npm 11.19.0, sodium native/WASM 1.0.22, bindings
0.2.5 / 0.8.4, esbuild 0.28.2 and Playwright Core 1.64.0 were exercised.
This is an experiment inventory, not an application release SBOM or professional
dependency/legal review. P03/P17 still own complete app scanning and release review.

## Preserved Windows reference

Owner-requested passkeylocal source/document snapshots retain their upstream
GPL-3.0-only license; the Microsoft ABI test header retains its own MIT notice.
Exact revisions, selected-file hashes and unchanged license copies are in
[reference provenance](reference/passkeylocal/PROVENANCE.json). The archives remain unchanged. Selected source is now adapted into the
separate GPL-3.0-only experiments/p01/windows-hello crate, with its modifications
and original license notices retained; no native code is bundled in the PWA.
The experiment adds 108 resolved Cargo metadata package records, including the
private GPL-3.0-only root, in the inventory under windows_hello_rust_packages.
This is not a release distribution assessment. The rest of AnyNote's release
license remains unselected.

## Export fault / device-capture slice

No Cargo/npm packages or lockfiles changed. Native collector scripts remain
inside the GPL-3.0-only Windows experiment; the rest of the project still has
no chosen release license. Optional mkcert is referenced solely as a manual
local certificate procedure, not installed, executed or added as a runtime
dependency. Its official release/README observation is documented in
P01_PRIVATE_HTTPS_WINDOWS.md; no asset digest or trust provisioning is claimed.

## Simplified device kit

No new Cargo/npm packages or lockfile resolutions. The existing windows-sys
crate adds its Shell API feature to open the owned report folder. MSVC target configuration
links the CRT statically for the Windows test EXE. Scoped GPL license is embedded
and exact corresponding source is linked from the GitHub prerelease. The iPhone
ZIP bundles only existing exact sodium JS/WASM dependencies, their actual ISC
license files, original generated PNG icons and local static assets; no native
GPL adapter is bundled. esbuild/Playwright/Python are build/test tools, not owner
runtime requirements. Whole-project licensing remains unselected.

## P03 resolved foundation inventory

Primary sources checked 2026-10-11 supersede P00 candidates: PHP 8.4.26,
Composer 2.10.3, MariaDB 11.8.9 LTS and stable Nginx 1.30.5. PHP/Nginx official
images use Debian trixie; MariaDB uses Ubuntu 24.04 noble; the cloud host remains
Debian 13.6. No host packages installed. Exact digests/sources: infra/dev/versions.json.
Signed Debian libicu-dev 76.1-4 and libzip-dev 1.11.3-2 support PHP builds; indirect
OS packages remain repository-resolved, not a byte-identical release/SBOM claim.

Laravel 13.35.0 is frozen with 73 runtime/26 development packages in the Composer
lock. apps/api/dependency-inventory.json has 99 exact source/dist/license records;
upstream empty dist checksums remain empty, never invented. Pint 1.32.1 MIT and
PHPUnit 12.5.38 BSD-3-Clause are development-only. Upstream skeleton provenance:
apps/api/UPSTREAM.md; no default auth model/migrations/Tinker/UI copied.

Gitleaks 8.30.1 MIT is an official checksum-verified Linux x64 development scanner,
not an application dependency. Its source/asset SHA-256 is in the installer.
Three scanner negatives validate narrow reference/source-input checksum allowlists.
Composer's proprietary root marker expresses no selected redistribution grant,
not a chosen future release license. P01/GPL boundaries remain unchanged.

## P02 candidate serialization tooling

Node 24.21.0/npm 11.19.0 reference package packages/protocol pins canonicalize
5.1.0 (Apache-2.0), jsonc-parser 3.3.1 (MIT), Ajv 8.20.0 (MIT) and all four
transitives in package-lock.json. Seven installed upstream license notices
inspected; exact registry SRI/source/license inventory is committed. Primary
metadata/README/RFC evidence: evidence/p02-primary-sources.json. Project release
license remains UNSELECTED; root package is private UNLICENSED, not an assertion
that dependencies lack licenses. No new lifecycle scripts, crypto primitives,
GPL adapter imports or production/native/browser JCS compatibility claim.


## P02 identity/recipient candidate additions

@scure/base 2.4.0 MIT provides established Bech32m, with no production transitive
packages. libsodium-wrappers-sumo and explicitly overridden libsodium-sumo 0.8.4
ISC reuse WASM sodium 1.0.22 already exercised in P01. Exact frozen npm inventory
now contains ten packages; licenses/SRI/source metadata checked in
[evidence](evidence/p02-identity-primary-sources.json). No lifecycle script,
GPL adapter import or project release license change. Node 24.21.0 built-in HKDF
uses its existing upstream runtime/license; no new HKDF implementation dependency.

Pinned foundation PHP 8.4.26 native sodium reports 1.0.18 from the image's signed
OS packages. Actual primitive/vector interoperability is tested, not selection
of this OS version as a future production crypto baseline. Scure README names
external review of 1.0.0 and self-review of 2.2.0; neither is review evidence for
selected 2.4.0 or this candidate. No signature/provenance verification or full
OS license SBOM is claimed from registry SRI and inspected notices.

## P02 complete export reference tooling

Rust age 0.12.1/rage 0.12.1 (MIT OR Apache-2.0), independent Go age 1.3.2
(BSD-3-Clause). Actual tagged workspace/license and official GitHub release
asset digest metadata verified on 2026-10-11; exact public Linux artifact pins
in packages/contracts/p02-export-tools.json. Ignored synthetic tools only,
no product dependency/lock change or release SBOM/signature/Sigsum claim.
Existing Node crypto/libsodium and pinned native PHP sodium/OpenSSL reproduce
new note/local/PRF/Argon/AES-GCM bytes. A transient Prettier 3.6.2 formatting
invocation changes source formatting only; it is not a product/setup dependency.
