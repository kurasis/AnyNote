# P17 evidence index

See [security evaluation](../../P17_SECURITY_REVIEW.md), [all24 threat bindings](../../security/P17_TRACEABILITY.md)
and [exact advisory triage](../../security/p17-advisory-triage.json).

Ordinary PR/main acceptance requires all30 jobs: every29 inherited job plus
`adversarial-linux`. The new artifact `p17-security-report` contains original
fuzz, portable, HTTP, supply-chain, traceability, remediation and source reports.
Development/dirty-source results are separate and never final acceptance.

Final exact-head cohort, immutable Git blob audit, source-tree qualification,
original report bytes and GitHub artifact ZIP digests are preserved on the
[P17 final evidence branch](https://github.com/kurasis/AnyNote/tree/evidence/p17-final/docs/evidence/p17/final).
The merged PR links the immutable archive commit after push/readback. This index
does not itself assert that a pending or failed cohort has passed.

The archive preserves declared source SHAs, including inherited synthetic merge
objects where applicable, and never rewrites raw reports or normalizes CRLF.
Archive-only exact false-positive bindings, if needed, extend the unchanged source
secret policy and are independently bound to actual receipt/Git bytes. No private
SQL snapshot, key, recovery kit, secret canary or private runtime log is published.

Interpretation: actual1GB/Windows/PWA/SQL/restore/capacity evidence remains scoped
to those jobs. The P17 extra file is1MiB+1, not a replacement gigabyte. Live OSV
findings are retained with scope, not erased by a passing aggregate status.
Qualified independent review is TRACKED_NOT_BOOKED / NOT_RUN. Production release,
physical matrix, memory budgets and actual100GB remain open.
