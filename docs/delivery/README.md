# GitHub delivery index

The owner requested GitHub publication of completed deliverables as the default.
See [the delivery policy](../DELIVERY_POLICY.md).

## 0.18.0-review.1

Release page: https://github.com/kurasis/AnyNote/releases/tag/v0.18.0-review.1

Exact application source: `c52af68046f98e55fab904f2f9bfd3984e54498a`.
Windows native binary version: **0.14.0**, default release profile without the UI
integration harness. The installer is unsigned. PWA assets retain their actual
tested origin `https://api.anynote.test:18443`; a custom origin requires rebuilding
and verifying the static output as described in the deployment guide.

The release attachments include the Windows installer, full Windows/API/PWA/source
delivery ZIP, short and complete Russian deployment guides, rebuilding instructions,
an external verifier and public environment template, all checksums, and the
complete offline reviewer handoff with its companion verification kit.

The source application's ordinary PR and independently observed main cohorts each
passed all 30 jobs. All 1,192 files in the delivery ZIP passed CRC/length/SHA-256
roundtrip checks. The offline handoff retains 155 original CI ZIPs across six
cohorts, including original failures/cancellations, both final three-candidate
sets and original CI Git objects. Its final source audits reproduced 14,184 Git
input rows per cohort in a fresh local object store without a remote.

The publication job reconstructs the existing packages from original CI ZIPs and
retained public inputs, requires exact matches with all original local asset
hashes, verifies GitHub's uploaded asset digests and only then publishes this
prerelease. Application binaries are not recompiled or re-signed by that job.

Production release eligibility remains **BLOCKED**. Qualified independent review,
physical iPhone/Windows/memory/PRF/Hello/TPM, real 100 GB capacity, production
signing and key/operator custody, and the repository-wide release-license decision
remain external gates. No production deployment is performed by publication.

Original immutable software evidence:
https://github.com/kurasis/AnyNote/tree/5df3aa7c85fabad8c5b36a2502f733bd0aa47351/docs/evidence/windows-memory/final
