# Initial dependency and license inventory

P00 candidate inventory, checked 2026-10-10. No application dependency manifests,
transitive lockfiles, vendored code or release artifacts exist yet. This is not
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
