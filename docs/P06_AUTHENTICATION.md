# P06 account authentication and sessions

Implementation scope: original chapters 05, 08, 13, 14 and 20; frozen P02
identity/state bytes; durable P04 authority and P05 client primitives. This is
account authentication, not persistent local custody, device enrollment/reset,
content UI, physical Windows Hello eligibility or production release.

## Maintained verifiers and dependency preservation

PHP uses `web-auth/webauthn-lib` **5.3.9**, `web-auth/cose-lib` 4.8.2 and maintained
CBOR/serializer/ceremony implementations. The exact configured app HTTPS origin
and RP ID are required, user verification is required, and both ES256 and RS256
are advertised. None attestation does not attest TPM binding or physical UV.
The library's null logger/event dispatcher stay unattached to request logging.
Strict client-data JSON precedes maintained signature/counter/origin validation.

Native grants use `league/oauth2-server` **9.4.1**, its authorization-code and
refresh grants, maintained Defuse encryption and signed access-token generation.
The native client uses Rust `oauth2` **5.0.0**, reqwest 0.12.28 with native trust
roots, `webbrowser` 1.2.4 and httparse 1.10.1. It does not implement a replacement
OAuth grant or trust client-decoded JWT claims. Additional private CA bytes come
only from independently trusted installation configuration. TLS verification,
hostname validation and the Chromium sandbox remain enabled.

Primary package records are available at
[Packagist WebAuthn](https://repo.packagist.org/p2/web-auth/webauthn-lib.json),
[Packagist League](https://repo.packagist.org/p2/league/oauth2-server.json) and
[crates.io OAuth2](https://crates.io/api/v1/crates/oauth2/5.0.0).
Composer's manifest permits patch releases; frozen installation and the explicit
compatibility gate admit only the reviewed locked versions. All **103 P04
package records** remain identical. There are **23 approved additions**, with
an exact P04 baseline copy and checksum, a purpose-specific receipt, complete
126-package inventory and recomputed-checksum tamper negatives. The native
adapter has its own 188-record lock/license inventory. The lock is marked
`-text` so Windows checkout preserves its exact reviewed SHA-256 bytes. Prior P02/P04/P05 inputs
remain frozen. These records are not an independent audit or release license.

## Atomic registration and authentication

`accounts:bootstrap-invite --hours=48` creates one expiring, hashed invitation
when no account exists. It prints the token once to the operator console.
Registration first verifies a passkey in a bound anonymous browser ceremony,
then obtains a 60-second P02 challenge for the client-generated public identity
and first device. The device signs the challenge and decrypts a sealed secret;
neither a device ID nor one key alone suffices. The client root signs the initial
device certificate and roster event. The API validates frozen purposes, service,
account/root/session, both public keys, sorted capabilities, generation/version
zero, null predecessor and the signed five-device limit.

One transaction consumes the invitation and creates the account, immutable
public root identity, active first device, roster event, passkey and only the
bound trusted session. Failed registration leaves no partial identity. Concurrent
anonymous retries produce one successful session; stale anonymous requests
cannot acquire a second credential. A retry using the resulting browser session
returns the same public receipt for 30 days. A changed request fails. No reusable
bearer secret is stored in a receipt. `accounts:bootstrap-admin ACCOUNT_ID`
promotes the existing first identity through the separate operator console;
it neither supplies a root nor grants any group membership.

Later passkey login and authentication recovery always create a **restricted**
session. Login options have no account handle or credential list. Adding a
passkey requires a current session, recent authentication and UV; deleting the
last method requires an unconsumed authentication recovery code. Ten random
256-bit recovery codes are stored as independent hashes, replaced atomically
and consumed once. They restore account access and never recover R or content.
The initial root/R are generated client-side with maintained P05 primitives.
Only public frames reach the API. A small explicit offline-kit download occurs
before the account is committed. A closed P06 outer export adds the service URL
and explicit offline/recovery instructions while keeping the frozen P02 kit
unchanged. Its URL is a human hint, never connection authority; future recovery
must compare independent service/account/root pins. It is client-only, never an
accepted API request. Root/device private bytes are wiped as practical;
durable custody and recovery/enrollment UI are P07/P08, not plaintext web storage.
Private preference-group genesis belongs to P08/P09 before preference writes.

## PWA transport and lifecycle

Serve the static app and API on separately controlled sibling **HTTPS** origins
within the same registrable site. Set exact `ANYNOTE_APP_ORIGIN`,
`ANYNOTE_API_ISSUER`, `ANYNOTE_RP_ID` and stable `ANYNOTE_SERVICE_ID`. Configure
the edge's exact API host and trusted FastCGI HTTPS signal; client-forwarded
headers cannot substitute for TLS. Authentication fails closed when origins,
service identity or matching RSA keys are missing. The API trusted-host pattern
comes from the configured issuer and is escaped, never from request headers.

The encrypted Laravel database session contains the internal opaque auth secret.
Its sole cookie is `__Host-vault_session`, Secure, HttpOnly, Path=/, no Domain,
SameSite=Strict. `GET /auth/csrf` returns a synchronizer token only to the exact
app origin. Every PWA mutation, including anonymous enrollment/login, uses
`X-CSRF-TOKEN`. Laravel's actual token validator remains enabled, including
tests; Laravel 13's Fetch Metadata shortcut is disabled. No readable parent
XSRF cookie or web-storage token exists. Rotation returns/reacquires the CSRF
token. The client coalesces simultaneous CSRF acquisition and bounds response
streams before assembling them. Cookies and bearer headers cannot be combined.

PWA idle timeout is **30 minutes**, absolute timeout **30 days**; native access
is at most **15 minutes**, refresh/family lifetime at most **30 days**. Recent
authentication lasts **five minutes** and is separate from device proof. Expired
browser cookies can restart login; idempotent logout clears expired/disabled
browser state. Lists and account session caps include refreshable native families
and exclude expired PWA sessions/abandoned native codes. Revocation invalidates
the stable session and associated codes, access identifiers and refresh family.
IP/browser admission counters commit independently of denied ceremonies. Active
session/passkey/pending ceremony caps bound work. Scheduled `auth:prune` performs
bounded expiry cleanup, preserving used refresh hashes and registration receipts
through their full acceptance lifetime; it never deletes roots, devices or content.

Session upgrade requires a new 60-second P02 both-key possession proof bound to
the session ID, current durable certificate, root, service, generation and roster
head. Every trusted call reloads durable account/device authority. Re-login never
reuses previous proof. A revoked/disabled device or changed generation denies
trusted access. The explicit commitment is SHA-256 of
`AnyNote/P06/device-key-commitment\0 || signing_public32 || encryption_public32`.
Session binding is SHA-256 of `AnyNote/P06/session-binding\0 || session_id_b64`.
They are base64url encoded; the separators are actual NUL bytes.

## Native handoff and rotation

The only public client is `anynote-windows`, with no client secret. The adapter
binds a fresh literal 127.0.0.1 or [::1] port and `/callback/RANDOM_16_BYTE_ID`
path. The maintained OAuth client creates random 32-byte state and PKCE S256.
`GET /auth/native/authorize` records the exact redirect, state, issuer and intended
device-key commitment and returns the fixed app's consent URL. The app shows
that commitment and local callback, binds consent to its current browser session
and requires explicit recent-authenticated approval. Approval creates a **new
restricted native session**, not a copy of the browser's device proof.

The maintained code expires in 60 seconds, is single-use and resolves to the
scoped public-client/redirect/account/native-session/device commitment. The
callback carries only code/state/iss. Native tokens are returned only to the
origin-free, cookie-free native token endpoint; API JavaScript cannot redeem a
native grant. The JSON transport adapter preserves maintained OAuth2 PKCE/grant
construction while matching the strict AnyNote DTO. It performs no redirects.

The listener enforces exact raw path, Host, GET, bounded headers/read/deadline,
single code/state/iss, expected issuer/state, no bearer/cookie/body/token fields,
IPv4/IPv6 loopback only and one successful callback. A wrong callback returns a
static denial without consuming the legitimate attempt. Dropping `Pending`
closes the listener. The system browser entry point is real; the explicit
`integration-harness` feature supplies a synthetic network resolver/test CLI,
never an API verifier bypass or a production credential logger.

SQL retains only refresh hashes/nonsecret library revocation identifiers.
Access JWTs are accepted only by their complete exact minted-token SHA-256 hash
and current durable session authority; decoded JWT roles are never trusted.
Rotation preserves the stable session/device proof only while the same current
certificate/commitment/generation is valid, changes the access hash and consumes
the old refresh. Reuse commits revocation of the entire family even when the
request is denied. Expected denial is caught outside a nested savepoint so a
failed verifier cannot commit partial enrollment/token issuance. Absolute expiry
never extends on rotation. Native credential wrappers redact Debug and wipe
owned token strings; persistent protection/local lock are P07 responsibilities.

## Executable contracts, UI and checks

The generated PHP/TypeScript/OpenAPI boundary has 83 declared operations,
196 types and **23 executable P06 routes**, all with closed typed DTOs. Remaining
content/pairing/reset/policy routes keep their future phase ownership. The
account-security static UI supports passkey login/register/add/reauth/removal,
one-use authentication recovery, session list/revoke/logout and native consent.
DOM output uses text nodes. Maintained Ajv standalone compilation runs at build
time; the shipped strict CSP needs neither inline scripts nor JavaScript eval.
Wasm compilation alone is enabled for maintained sodium. Static hosting never
executes PHP, exposes SQL/private paths or receives native bearer tokens.

Development-only commands (do not apply disposable DB resets to live data):

```sh
source scripts/runtime-env.sh
python3 scripts/check-p06.py
python3 scripts/p06-native-inventory.py
python3 scripts/p03-contracts.py
cargo fmt --manifest-path packages/auth-native/Cargo.toml --check
cargo clippy --manifest-path packages/auth-native/Cargo.toml --locked --all-targets --all-features -j 4 -- -D warnings
cargo build --manifest-path packages/auth-native/Cargo.toml --locked --features integration-harness -j 4
python3 scripts/p06-stack.py reset
node packages/protocol/p06-http.mjs
python3 scripts/p06-stack.py reset
node experiments/p01/p06-browser.mjs
python3 scripts/p06-evidence.py linux
```

`up`/`check` verify real TLS, static/API separation, encrypted SQL session/cookie,
CSRF and hostile-origin denial and preserve an already owned database. Only
explicit `reset` replaces the marked `anynote_p06_tests` database. Test CA and
OAuth keys live in ignored, owner-marked directories with private files mode
0600. HTTP tests use maintained Node P-256 fixtures and the actual PHP verifier;
the mandatory browser gate uses resident UV CDP credentials in the real shipped
UI. The native integration traverses maintained Rust OAuth2, real HTTPS, PHP
League, a real TCP callback and refresh/reuse. Reports contain metadata only.
Eight-request registration/refresh races use eight actual PHP-FPM workers.
Rate admission reads the current bucket under an exclusive lock before mutation,
with bounded transaction retry for concurrent first insertion and expired windows reset
under that lock and expired-bucket cleanup in maintenance. A 64-request test in
eight concurrent waves admits exactly 60 and returns four typed rate denials.
Run the P03 outage suite and P06 HTTP suite sequentially: P03 deliberately stops
their shared, owned MariaDB service.

Acceptance evidence is in TEST_EVIDENCE.md. Local sandbox BLOCKED is never a
browser pass. The Windows-only stdlib evidence helpers use maintained CPython 3.14.8 because
3.12.14 has no maintained Windows x64 artifact; cloud/Linux remain 3.12.14.
Windows/MSVC callback tests are hosted software tests, not a new
owner-device Hello trial. Full P01 physical/memory/network and independent G2/G3
review remain open. No production migration/deployment, release or outreach is
authorized/performed by this phase. Production rollback needs a data-preserving
operator plan; the new migration intentionally has no destructive `down` helper.
