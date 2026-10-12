# Next implementation batch

## Complete P09 private groups and encrypted notes

Confirm final P08 tracking, acceptance receipts and passing final CI first. Read
AGENTS.md, PROGRESS.md, TEST_EVIDENCE.md, DECISIONS.md, KNOWN_LIMITATIONS.md,
P04_BACKEND.md, P05_CRYPTO_CORE.md, P07_LOCAL_VAULT.md, P08_TRUSTED_DEVICES.md,
and original specification 01, 04, 07–09, 13, 14 and relevant 20 criteria.
Use the existing checkout, Russian chat and English source/docs/commits. Ordinary
passing PRs and automatic push/merge are already authorized; no worktrees or
subagents unless expressly requested. No production deployment/migration, release,
new owner-device trial or reviewer outreach.

Restore owned services with runtime-env.sh, dev-stack.py up/check and
p06-stack.py up/check. The published P07 setup was actually restored; the tested
P08 draft is distinct from publication/fresh P08 snapshot restoration. Preserve
owner-marked credentials/TLS/OAuth files and SQL volumes. Source setup is read-only;
never regenerate frozen corpora, old locks or generated contract outputs for a
pass. P03 outage tests must run sequentially with auth/device HTTP tests.

Implement the complete first private-note vertical slice: real private groups,
encrypted group/thread titles, entries, safe Markdown/checklists, encrypted account
preferences, and clear local-save/server-save/unknown/conflict states. Root bootstrap
already creates the private settings group and full device+recovery grant coverage.
Extend that verified group-c2 machinery to actual private-group creation; do not
replace it with a placeholder group or server plaintext. Use random group/object
keys and maintained P05 frozen codecs, signatures, AAD and recipient contexts.
Device/session trust, local unlock and group authority remain distinct.

Connect real P04 scoped persistence, authorization and atomic revision/quota/
receipt/sync-event publication to typed implemented API operations. Validate current
roster/policy/epoch at publication and historical evidence at read. Existing P07
acknowledged encrypted drafts/outbox must survive failed requests and restart;
immutable attempts and receipts resolve unknown results without duplicate writes.
Keep signed parents/author/context and decrypted internal references consistent.
Respect revocation/rekey/history-closure flags; general membership/epoch maintenance
is P10, never bypass those flags to satisfy a note test. Retain unresolved work and
provide an explicit blocked state where later-phase maintenance is required.

Build a small usable private-vault UI and corresponding protected native commands
without exporting L/device/group private keys through general IPC. Render user
content through safe components, never arbitrary HTML/script or a relaxed CSP.
Support a note created by actual native Windows/core custody and read by an enrolled
PWA client, and the reverse; full host/PWA packaging is P14/P15. Inspect real SQL,
IndexedDB/SQLite, caches, logs and errors for plaintext/key/token leakage. Include
meaningful cross-account/current-access/tamper/replay/unknown-result/concurrent-edit/
quota/lock-restart and unsafe-Markdown tests over actual HTTP and persistent storage.

Preserve P08 independent root pins, both QR directions, one-use approvals,
transitive revoke and root-signed CAS recovery. Do not authorize recipients or
historical writers from signature validity alone. Keep root/R transient, private
keys under random L, epoch/writer/generation fencing and original strong-phrase/
Hello/PRF eligibility. Native/browser local control IDs and AAD hash JCS bytes.
The public bootstrap journal commits atomically with keys and resolves interrupted
registration without persisting R. An old whole backup cannot establish universal
freshness. Current bounded account roster is 1,000 events, signed device cap 1–32
(default5), QR transport rather than an invented short-code/SAS scheme.

Run all prior required jobs plus appropriate mandatory P09 browser/native/Windows
acceptance at the exact final head/tree. Archive only public exact-source receipts;
update README, progress, decisions, limitations, evidence, development/setup and
NEXT_TASK for full P10. Physical G1/Hello/iPhone and qualified G2/G3 review remain
open/unbooked/NOT_RUN; software CI is not production security-release acceptance.
P11 owns sync/history scale, P12 file-source/resume, P13 export/restore, P14/P15
product packaging, P16 operations and P17 qualified adversarial review.
