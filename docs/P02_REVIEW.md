# P02 qualified review tracking and candidate findings

P02 design/fixture deliverables are complete when their automated gates pass.
Original chapter 14 §5 requires review **scheduled/tracked**, not a fabricated
completed audit. This file and `packages/contracts/p02-review.json` track it.
Status: **TRACKED_NOT_BOOKED / NOT_RUN**. Reviewer: unassigned. Booking/report
links and dates: absent. Production/security release remains blocked until a
qualified independent reviewer examines the exact implemented composition and
all required findings are remediated/retested. P17 owns final release review.
Self-review, library audits, CI or public test keys are not qualified AnyNote review.

## Review package and checklist

Start at protocol-v1.md, P02_COMPLETE_CONTRACT.md and the identity/state/group
contracts; follow the component/schema/hash registry and complete PUBLIC byte
vectors. Review both client expected-context derivation and product-server
transaction/session design, not just primitive algorithms.

- R01 key hierarchy/domains/nonce independence; distinct root/recovery/device/G/L/export paths.
- R02 login versus local unlock versus device activation; actual provider/PRF fallback policy.
- R03 local lock/suspend/reload generations, GC copies, session/outbox encryption and owned cleanup.
- R04 root kits/Bech32m, pin authenticity, deliberate recovery custody, compromised-root migration.
- R05 QR authenticated secretstream/transcript/direction/one-use/OOB entropy and owner intent.
- R06 delegate ancestry, dual-key possession, descendant revoke, cap changes and reset races.
- R07 active sessions/challenges, recent auth for sensitive transfer/reset, replay after receipt expiry.
- R08 policy owner/editor/reader, twenty-member cap, complete current and retained-epoch recipient coverage.
- R09 pending admission/staging/head CAS; cancellation burns exposed G; wrong-key repair.
- R10 simultaneous roster revoke/member removal/rekey, no stale recipient grants or reader write escalation.
- R11 signed placement/attachments/archive/tombstones; decrypted context equality; conflicts/restore.
- R12 file manifest/DEK/nonces/chunks/size/hostile framing; 1 GB production transfer and quota binding.
- R13 independent history witness, full parent closure/pruning, c1/c2 profile separation and server forks.
- R14 transport generation/commit order/idempotency/unknown outcome/snapshot pins and revocation.
- R15 restored-server independent security fence outside backups; no restored credential resurrection.
- R16 standard age v1 maintained implementation, native packaging/licenses and fresh export identity.
- R17 strict USTAR path/metadata/count/observed-byte limits, footer/EOF and complete selected source inventory.
- R18 every cross-account author/roster/policy/accepted revision; independent kit rather than embedded trust.
- R19 selected-DEK-only export, offline original-key paths, temporary secrecy and no early import mutation.
- R20 current-only/history/trash/pruned selection, new private destination IDs/keys/provenance.
- R21 weak/unavailable PRF/provider downgrade, endpoint/PWA-origin compromise and offline guessing limits.
- R22 malicious transport/operator metadata/traffic/availability; no invented global freshness/FS.
- R23 general Rust/browser/PHP parser/crypto interoperability, Unicode/DoS and full product budgets.
- R24 actual Windows/iPhone lifecycle, secure IPC/update/deployment/backup and measured release artifact gates.

## Findings discovered during candidate completion

| Finding | Resolution / follow-up |
| --- | --- |
| F01 Previous group candidate caps 10 instead of required 20 | Resolved by explicit c2 profile, separate domains, immutable legacy vectors and authenticated twenty-account / 800-grant test |
| F02 Greedy page test attempts >1 MiB through a 1 MiB parser | Resolved by canonical-size check over already typed values before admission; real multi-page twenty-account regression |
| F03 New note/local schema inherited old 1 MiB canonicalizer | Resolved by independent bounded JCS path and actual 2 MiB boundary test; local ciphertext permits base64 overhead |
| F04 Generic native opaque blob is not an exact format | Resolved by concrete versioned PRF/TPM/machine/AES-GCM byte profile; actual native eligibility/lifecycle remains a P05/P07/P14 release gate |
| F05 age decryption alone leaves authorship/EOF/selection ambiguous | Resolved by independent kit, c2 author/history closure, exact selected source pages, original note/file DEKs, signed complete inventory/footer and no live mutation |
| F06 Uncertain send/receipt expiry can duplicate a publication | Resolved in contract/model by immutable attempt/revision digest, CAS, preserved SENT_UNKNOWN and current read authorization for already committed attempts after writer-role loss; SQL durability/concurrency remains P04/P11 |
| F07 Upstream source scanner truncates decoded huge vectors | Use complete JSON-value byte blocks and only full exact PUBLIC exceptions; all changed-field/token/alternate-age-key negatives remain mandatory |
| F08 Old tracking mistakenly makes product SQL/adapters and performed audit part of P02 exit | Correct scope against original P02/P05/P07/P13/P17; no gate silently marked passed |

Open candidate assumptions requiring independent review: trustworthy OOB pins and
owner ceremonies; endpoint/origin compromise; account-auth/device-state authority
and lock-order composition; hardware provider eligibility; practical secret
lifetime; large-history streaming/checkpoint bounds; archive overhead/source lease
choices; reauthorization/import atomicity. Product-phase work must not treat this
candidate as approval. A required design change creates a new explicit profile,
reviewed vectors/compatibility/migration decision, rather than changing old bytes.

Booking action for the project owner: appoint a qualified independent protocol
reviewer and attach schedule/scope/report/remediation evidence here. This task
has not contacted anyone or made a booking. Development of later synthetic
phases may continue; shipping/use with security-sensitive data may not.
