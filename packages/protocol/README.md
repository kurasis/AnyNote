# Candidate protocol codecs

P02 `p02-file-c1` only. Read [the contract](../../docs/protocol-v1.md) before use.
Private/unlicensed project package; dependency notices/licenses remain upstream.
This Node test/reference harness does not authorize operations, perform AEAD,
signatures, key custody or become a deployable browser/native application.

Exact dependency/source/license records: package-lock.json,
dependency-inventory.json and [primary-source evidence](../../docs/evidence/p02-primary-sources.json).
canonicalize 5.1.0 (Apache-2.0) supplies RFC 8785; jsonc-parser 3.3.1 (MIT)
supplies syntax visitor callbacks before JSON.parse; Ajv 8.20.0 (MIT) enforces
strict draft 2020-12 schemas. Installed upstream license notices were inspected.
Project release license remains unselected. No GPL Windows reference code is
imported here. Cross-platform production library selection remains pending.

From repository root activate scripts/runtime-env.sh, frozen-install using
`npm --prefix packages/protocol ci --ignore-scripts --cache /workspace/.cache/npm`,
then `npm --prefix packages/protocol test`, `npm --prefix packages/protocol run
fixtures:check`, `npm --prefix packages/protocol run inventory:check` and
`python3 scripts/check-p02-fixtures.py`. CI runs the same checks plus advisory
and baseline integrity checks. Regeneration commands `fixtures:write` /
`inventory:write` change reviewed files and require diff review, never setup.

Subsequent [pinned device-state candidate](../../docs/P02_STATE_CONTRACT.md)
adds pairing/activation/revoke/reset verification in separate APIs. This does not
change these original signature-only bytes or grant group policy/history rights.
