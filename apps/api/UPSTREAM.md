# Laravel skeleton provenance

Selected bootstrap, config, public front-controller, Artisan, provider and test
base files originate from laravel/laravel v13.11.0, commit
`06d016a364a37430eec9cbc52209adce3d7667ce` (MIT per upstream Composer metadata).
GitHub archive SHA-256:
`544ee1a789b7f6beff50acd7b331511e61b85e1c24ec89a6386b58508e5df961`.
Source: https://github.com/laravel/laravel/tree/06d016a364a37430eec9cbc52209adce3d7667ce.
The upstream archive has no standalone license file; its README links MIT.
Resolved dependencies retain their actual licenses in vendor/ and the inventory.
AnyNote's project release license remains unselected.
The root Composer `proprietary` marker means no open-source redistribution grant
has been selected; it does not choose a future release license or alter upstream MIT.

The product models, migrations, auth/password flows, welcome UI, SQLite database,
Tinker, frontend toolchain and skeleton automatic migration/setup scripts are
excluded. Host validation, development-only readiness and temporary transaction
checks are AnyNote foundation additions. Framework APP_KEY is a disposable
Laravel runtime key, never the content-encryption or account-recovery key.
