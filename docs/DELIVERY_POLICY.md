# Owner delivery publication preference

The owner requested that completed deliverables be uploaded to GitHub and that
this remain the default for subsequent work in kurasis/AnyNote.

- Publish completed source/documentation through the normal repository workflow.
- Publish large installers, build archives and offline review sets as GitHub
  release assets rather than large Git blobs.
- Include downloadable guides, exact source identifiers, checksums and actual
  validation results. Return GitHub links in the user-facing handoff.
- Preserve the actual version, signing status, review scope and release blockers.
  Current 0.18.0-review delivery retains Windows binary version 0.14.0, absent
  Authenticode and the tested PWA API origin. Mark it as a prerelease and do not
  promote it to the latest production release.
- Keep raw original evidence and failed/superseded results unchanged. Preserve
  existing credentials and use the configured GitHub connection.
- Production deployment, real key collection, external reviewer outreach and
  closure of physical/security/license/custody gates require their applicable
  authorization and evidence. Publishing a review prerelease does not close them.

This policy records the owner's request of 18 October 2026. It governs delivery
location and defaults, while the existing repository safeguards continue to apply.
