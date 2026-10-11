# Candidate schema registry

`registry.json` selects the bounded **candidate** `p02-file-c1` schema definitions.
The JSON schema and additional predicates in ../protocol/src/codec.mjs are jointly
required; JSON schema alone cannot prove ordered inventory arithmetic, ancestry,
expected context, authenticity or authorization. Every object is closed to
unknown fields. `docs/protocol-v1.md` defines exact encoding and trust limits.

This registry is not the complete v1 freeze or product OpenAPI/TS/Rust/PHP types.
There is no API endpoint exposing these incomplete security transitions.

The [p02-state-c1 registry](p02-state-c1.registry.json) and
[state contract](../../docs/P02_STATE_CONTRACT.md) add synthetic authenticated
pairing and pinned signed-device state. Account login/SQL durability are simulated;
group policy/history authorization and physical QR verification remain pending.
