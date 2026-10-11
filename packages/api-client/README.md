# P03 API contract checks

Generated TypeScript declarations are `../contracts/generated/protocol.d.ts`.
The strict Node boundary imports the existing P02 parser/predicates and validates
all 157 structures. It is a tooling reference, not a production PWA/native adapter.

Use Node 24.21.0 / npm 11.19.0 and `npm ci --ignore-scripts` with a writable cache.
Run `npm run typecheck`, `npm run lint`, `npm test`, `npm run contracts:check`.
From repository root `bash scripts/p03-checks.sh` checks types/drift, actual owned
Laravel/MariaDB integration and HTTP through Nginx/FPM. Install dependencies and
verified development images first; see docs/P03_DEVELOPMENT.md.

`python3 scripts/p03-contracts.py --write` deliberately regenerates reviewed
contracts. Its default mode, setup and CI only read/compare. PHP readonly DTOs
encode primitive field types/required constructor fields; they do not validate
nested schemas, signatures or authorization. Runtime request-specific schema
and semantic acceptance belongs to P04/P05. Future operations have `never`
request/response types until a phase-owned transport wrapper is finalized;
existing closed P02 payload types are reused where appropriate.

Only two public foundation operations are implemented; every other OpenAPI path
is explicitly unimplemented. There are no dummy auth/crypto endpoints or generic
execute methods. Public capability features remain false. Local-only error codes
cannot be decoded as HTTP; fixed mappings and complete negotiated components are
mandatory. Production adapters must enforce HTTPS/exact issuer/origin, bounded
streaming, current authorization and all referenced P02 predicates.
