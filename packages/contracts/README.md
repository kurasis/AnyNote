# Candidate schema registry

`registry.json` selects the bounded **candidate** `p02-file-c1` schema definitions.
The JSON schema and additional predicates in ../protocol/src/codec.mjs are jointly
required; JSON schema alone cannot prove ordered inventory arithmetic, ancestry,
expected context, authenticity or authorization. Every object is closed to
unknown fields. `docs/protocol-v1.md` defines exact encoding and trust limits.

This registry is not the complete v1 freeze or product OpenAPI/TS/Rust/PHP types.
There is no API endpoint exposing these incomplete security transitions.
