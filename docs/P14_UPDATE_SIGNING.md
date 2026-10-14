# Windows update signing contract

Production Authenticode and updater private keys are not configured in this
development branch. The unsigned NSIS build is a development candidate.

An operator installs `update-policy.json` beside the app's `profiles` directory.
It contains a fixed HTTPS endpoint, the Tauri/minisign public key and the selected
`stable` or `candidate` channel. It contains no private signing key. The runtime
API and renderer cannot supply an endpoint or trust key.

Each updater response contains the normal Tauri server-format `version`, `url`
and `signature`, plus `anynote_claims` and `anynote_claims_signature`. The latter
is a second standard minisign signature over the canonical JSON bytes of:

```json
{"application_id":"org.anynote.desktop","artifact_sha256":"BASE64URL_SHA256","channel":"candidate","platform":"windows-x86_64","protocol":"anynote-update-v1","url":"https://OPERATOR/AnyNote.exe","version":"0.14.1"}
```

The native client verifies the claims with the operator's public key before
offering the update. It checks application, platform, channel, exact version,
HTTPS URL and artifact digest. It then uses the maintained Tauri updater's
payload-signature verification with `requireSignedVersion: true` and downgrade
protection enabled. The authenticated artifact digest must match the signed
claims before installation. Downloads are cancelled above 512 MiB or when the
vault generation changes. A failed update must leave the encrypted profile and
outbox in place; the installer does not own deletion of that data.

Publisher order:

1. Build the exact reviewed source and dependencies for Windows x64.
2. Authenticode-sign the installer with the production code-signing identity.
3. Compute its SHA-256 and create canonical claims with the final HTTPS URL.
4. Use the maintained Tauri CLI to sign both files, for example:
   `tauri signer sign --private-key-path OPERATOR_KEY --app-version 0.14.1 FILE`.
   One FILE is the final installer; the other is the canonical claims JSON.
   Passwords and private-key contents must not appear in command arguments,
   repository files, API configuration or application resources.
5. Put the two public detached signatures in the corresponding response fields.
6. Validate the exact metadata and artifact with the test client before release.

The public fixture in `fixtures/windows/p14/updates` was produced with the
maintained Tauri CLI. It contains no private key or executable installer. Its
tests exercise signature tampering and application/version/platform/channel/URL
binding. These tests do not claim a production-signed Windows upgrade or a
qualified security review.
