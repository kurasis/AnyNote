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
