# Next implementation batch

## P05 complete cryptographic core and interoperation

Read AGENTS.md, current tracking, original 04/13/14/20, frozen P02 contracts and
P04_BACKEND.md. Russian chat, English repository; existing checkout; normal
passing PR and automatic push/merge. No production deployment/release or new
owner trial is implied.

1. Complete maintained native/browser crypto adapters and strict general decoders:
   JCS (including RFC numeric/Unicode cases), Ed25519, XChaCha AEAD, identity/
   recipient/key wraps, file manifests and local wrapper formats. Reuse the P04
   public-signature slice without treating raw native signing as JSON validation
   or the PHP public-only canonicalizer as a general payload adapter.
2. Add deterministic PUBLIC cross-runtime corpora and actual Rust->browser /
   browser->Rust / PHP public signature acceptance. Test AAD/sender/epoch/key/
   length/JSON ambiguity, corrupt frames and nonce-reuse admission. Never reuse
   P02 private evaluation handles as product authorization.
3. Measure bounded workers/memory and preserve P01 physical/review limitations.
   Trusted client encrypted payload validation is separate from opaque server
   bytes; no plaintext fallback or server master-key acceptance.
4. Keep P04 SQL scopes/receipts/quota/counter ordering intact, extend OpenAPI only
   explicitly, retain frozen prior fixtures/locks, and update phase evidence /
   exact next task and verified read-only environment instructions.

P04's hosted signature result and final source verification are recorded in its
PR/evidence. Full P01 physical matrix and G2/G3 qualified review remain open;
reviewer is unassigned/unbooked/NOT_RUN. No new device run is required here.
