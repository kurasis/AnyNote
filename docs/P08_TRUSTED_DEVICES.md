# Trusted devices and account recovery

P08 implements software account trust and same-account key custody. Authentication,
trusted-device activation, local unlock and group permission remain separate.
The shipped development UI is `/auth/devices.html`; complete native/PWA product
packaging belongs to P14/P15. This is not a production security-release claim.

## Bootstrap and independent trust

Account registration generates R and both root purposes transiently in the Worker.
Download the offline kit and verify the selected account/secret information before
committing independent device keys and an immutable public registration journal
atomically under random L, then completing registration. A restarted client retries
that same signed request or verifies the already accepted roster and proves its
current keys after fresh sign-in. An unaccepted expired attempt needs a new
registration; acknowledged encrypted state is retained. A crashed writer lease
expires after ten seconds; it is not bypassed.
A signed initial roster and private settings group-c2 genesis, including the
account-recovery envelope, precede preference writes. R/root private keys never
enter everyday vault records, HTTP requests, telemetry or server storage.

New installations require the complete root fingerprint from an existing trusted
device over an independent channel, or the offline kit. The API fingerprint alone
cannot establish trust. Compare account, configured HTTPS service, root and new
device fingerprint on both displays before approving and activating. Each
installation creates fresh independent signing/encryption keys under P07 custody.

## Pairing and interrupted work

An existing device displays an invitation QR for a new phone, or a new installation
displays its offer QR for an existing device. Camera decoding uses maintained ZXing;
a privately transferred QR PNG is the authenticated independent-channel fallback.
There is no six-digit SAS/password fallback in the frozen QR protocol. Keep the QR
private; the channel key is transient and never uploaded to the relay. Relayed
frames are bounded secretstream ciphertext with exact purpose/direction/anchor,
expiry and replay checks. A pending approval supplies neither active trust nor keys.

Both parties explicitly confirm. SQL serializes account/head CAS, activation,
receipt, session trust and the audience-scoped notification/sync event. Retry the
same immutable signed activation after an unknown result. A committed receipt
resolves it once. Lock/background/idle discards channel secrets; pre-signing
interruption requires cancellation and fresh session/device keys. Encrypted local
work is retained. A complete verified chain is committed atomically, with a known
checkpoint: partial download, signature failure or storage abort cannot replace it.
Known regressions/forks quarantine; the server cannot prove globally newest state.

The active-device cap is configured as `ANYNOTE_ACTIVE_DEVICE_LIMIT` (1–32,
default 5), then root-signed and stored at registration. Changing a service default
does not silently alter an existing account. Accounts retain at most 1,000 roster
events within the current bounded reader contract; exhaustion rejects a transition
rather than producing an unreadable chain. Pending requests and relay messages have
independent per-account/global caps and authenticated rate limits.

## Revocation and recovery

Review the exact descendant closure before revocation. The signed transaction
revokes parent/delegated descendants, related sessions and native authorization
codes, cancels obsolete approvals and marks affected groups for rekey/history
closure immediately. Independent siblings remain. Historical certificates remain
verifiable; revocation cannot erase plaintext already obtained by a device.

On a fresh installation, restore account sign-in separately, load the offline kit
in the trusted client and confirm its selected information. Request a one-use
challenge for the fresh keys/current head, then root-sign the reset. The server
accepts only its previously anchored root and CAS generation/head, upgrades only
the bound recovery session, and revokes every previous device/session/code.
Activation occurs **before** fetching recovery envelopes, avoiding a key deadlock.
Fetch envelopes only for currently authorized groups; unwrap locally and persist G
under L, then publish fresh same-account device grants. Private settings genesis
provides the P08 working group context. General group policy/epoch maintenance is
P10; note preferences/content are P09. Rekey/history flags remain until maintenance.

An administrator cannot reconstruct R or plaintext. If all kit/key copies are lost,
personal content is unrecoverable. If R is stolen, generation reset is insufficient:
use a new identity/migration and independently verify it. Do not enter the kit into
an untrusted website or include it in bug reports.

## Additive local storage and native boundary

Frozen P02 records/corpora and every prior dependency lock are unchanged.
`p08-local-v1` adds closed lifecycle control/roster-page records because the frozen
`cache.public-evidence` purpose accepts export-evidence only. Maintained
XChaCha20-Poly1305 uses L, a fresh nonce and JCS context bound to service/account/
device/profile/record/root/purpose, with `AnyNote/P08/local-lifecycle\0` AAD domain.
Deterministic control IDs and displayed device fingerprints also hash JCS bytes,
so property insertion order cannot change native/browser identity.
Control/pages and protected secret updates are atomic and writer/generation fenced;
generic save/evict cannot replace them. L rotation covers both old and additive
records. Old clients refuse unsupported additive operations rather than erase data.
Qualified composition/design review remains NOT_RUN.

The native library uses the actual SQLite vault and closed main-window IPC, current
opaque capability, OS lock/suspend generation fence and independent key generation.
No renderer private-key/R/G/SQL/path export is added. Public roster input is bounded
at 16 MiB plus bounded IPC framing; all other IPC retains its prior 8 MiB bound.
The synthetic feature-gated process harness exposes ciphertext inspection only to
tests. Native Hello/TPM/provider/official-header ABI gates remain independent;
software tests do not attest physical hardware.

## Verification

Run `scripts/check-p08.py`, serial native tests (`--test-threads=1`, respecting the
process-wide bounded Argon2 gate), the owned TLS/SQL `p08-http.mjs` harness and
sandboxed `p08-browser.mjs` UI harness. GitHub `trusted-devices.yml` requires Linux
HTTP/browser/native interoperability and Windows MSVC/native/official-header ABI.
`p08-evidence.py` accepts clean exact-source passes only. Reports exclude kit/QR/
private values. Physical owner-device acceptance and qualified G2/G3 remain open.
