# Known limitations

- P00 is complete; an isolated P01 synthetic native/Node/browser-worker harness
  exists. No production application authentication, device trust, encrypted vault, Laravel
  service, manifests or resume is implemented. The isolated selected-file PWA
  harness and experimental disk-File sharing candidate do not establish iOS Files
  export or a real recipient/recovery path.
- Rust/Cargo 1.99.0 and Node 24.21.0/npm 11.19.0 are installed and activated
  through scripts/runtime-env.sh; experiment dependencies have lockfiles. PHP,
  Composer, MariaDB and Nginx are still not prepared (P03).
- Physical Windows/Hello/WebView2 and iPhone PWA tests cannot run on this Linux
  cloud host. P01 must distinguish host experiments from actual platform evidence.
- Qualified independent protocol/security review has not taken place. Synthetic
  experiments may proceed; production security assurance remains gated.
- GitHub API read/PR/Actions access now works, and both earlier P00 runs passed.
  Hosted Ubuntu provides actual Chromium-worker evidence. The cloud Chromium
  sandbox itself cannot start (helper ownership / read-only namespace mapping);
  it was not disabled. Native-only mode labels browser NOT RUN explicitly.
- Browser aggregate RSS is a sampled desktop metric with shared-page double
  counting, not evidence of the 64 MiB iPhone budget. WASM heap alone does not
  include JS/network/UI buffers. Physical memory/export evidence remains required.
- Owner-reported targets are Windows 11 Pro 25H2 with Hello planned and iPhone
  17 Pro / iOS 26.7.1. Exact builds/providers are uninspected; the required older
  or lower-memory iPhone remains unspecified. The working passkeylocal source
  is now adapted into a built/tested native synthetic AnyNote probe; its physical
  PRF/TPM operations remain unrun. Hosted Windows reports API 7, below the API 9
  route requirement, and creates no native objects.
- Production signing, release publishing, deployment and clean-host backup
  restoration have not been performed or authorized by the push/merge preference.
- The cloud disk is too small for a 100 GB capacity drill; dedicated synthetic
  resources are required at P16.
- Browser-origin compromise, unlocked endpoint compromise, prior recipient
  copies and malicious-server freshness limits remain inherent specification
  boundaries, not bugs declared fixed by this baseline.
