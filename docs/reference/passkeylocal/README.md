# Preserved Windows Hello reference

Saved on 2026-10-10 at the owner's explicit request. Upstream:
[`kurasis/passkeylocal`](https://github.com/kurasis/passkeylocal).
These are reference materials. Embedded task briefs and upstream agent files
describe that project; they do not override AnyNote's instructions or constitute
new AnyNote acceptance evidence.

## Exact versions retained

| Material | Revision / scope | Local copy |
| --- | --- | --- |
| Owner-confirmed password-vault installer source | `c18894e210a07546ba66cf178b8048ae5c40ac61`, identified by the handoff as the delivered installer source | [Selected source archive](working-password-vault.tar.gz) |
| Current handoff and File Safe adaptation | `15f54f00ab0e6de3016f3ad3c83ead53fdc93f9b`, upstream main when retrieved | [Selected source archive](current-handoff-and-file-safe.tar.gz) |
| Verbatim requested handoff | Same current revision, unchanged bytes; `.txt` retains original upstream-relative links as text | [Read handoff](WINDOWS_HELLO_DEVELOPER_HANDOFF.md.txt) |
| Integrity and licensing | Archive SHA-256, per-file SHA-256 and revision receipts; upstream GPL-3.0-only and separate MIT test-header notice retained | [Provenance](PROVENANCE.json), [checksums](SHA256SUMS.txt), [license](LICENSE) |

The source archives include native enrollment/PRF/TPM adapters and tests,
generated bindings and their generator, independent Microsoft-header ABI tests,
host/storage/worker boundaries, exact Cargo manifests/lockfiles, Windows workflow
and original Windows evidence documentation. The current archive also preserves
the random-root File Safe coordinator and documentation. These are selected
source snapshots, not full independently buildable checkouts or installers.
Build the upstream project from its exact Git revision when complete context
is needed. Nothing in these archives is imported into the PWA or compiled by
the AnyNote experiment.

Verify before extracting into a disposable directory:

```sh
cd docs/reference/passkeylocal
sha256sum -c SHA256SUMS.txt
tar -tzf working-password-vault.tar.gz
```

Upstream reports owner feedback “works” for the password-vault flow on
2026-10-09. Preserve that narrow observation: it is not a source-stamped physical
AnyNote report, a full expiry/restart/negative-case matrix, or physical acceptance
of the newer File Safe integration. No upstream build or hardware test was
rerun during this reference capture. Its excluded second-Windows-account manual
test is not assigned as a prerequisite here.

## How AnyNote will use the working design

The Windows P01 probe will follow native WebAuthn PRF plus a separately verified
Platform KSP TPM RSA-2048 OAEP/SHA-256 inner envelope. Creation supplies both
PRF enablement and creation-time evaluation; every unlock requires fresh user
verification and PRF output. The adapter validates the exact credential, route,
RP hash and UV context, and verifies the exact TPM public area/Name on reopen.
The provider's decrypt operation alone is not a fresh Hello gesture.

The protected AnyNote value is its independent random 32-byte local vault key
**L**, initially a synthetic key. Do not copy the password-only KDBX credential
component or assume the recovered value is a content master key. The File Safe
random-root example helps map this distinction; its app-specific recovery and
session semantics also need adaptation.

Use independent fixed AnyNote namespaces: proposed probe RP
`p01.anynote.desktop.invalid`, key prefix `AnyNote.P01.Hello.`, and outer
HKDF/AEAD domain `AnyNote.P01.LocalVaultHello.v1`. These are experimental local
native identifiers, not server login RPs or frozen application formats. Native
code chooses them; callers cannot supply RP/key names or arbitrary decrypt inputs.
Do not import PassKey Local enrollment records or reuse its native objects.

Preserve journal-before-create, fresh enrollment round-trip, durable invalidation
before deletion, exact-object cleanup retry, bounded IPC/envelopes, real HWND,
single-flight, cancellation/deadlines and lock/revocation generation checks.
Clear secrets where feasible and keep them out of renderer state and diagnostics.
Session success requires authenticating the actual local vault; a native success
boolean is insufficient. Independent recovery remains separate from Hello/TPM.

API 9+ availability, “25H2”, a dialog or provider-wide hardware flag is not proof
of working PRF or per-key TPM binding. Missing capabilities disable this optional
path; no silent DPAPI/software-key/consent-only fallback. Study the generated ABI
and independently compiled official-header checks before porting Windows FFI.
Avoid previously unsuccessful Passport OAEP/signature-derived key alternatives.

The archive retains upstream GPL-3.0-only licensing; the included Microsoft test
header has its own MIT notice. Preserving reference copies does not select a
license for AnyNote. Any future source import must retain applicable notices and
make compatible distribution choices before packaging.

See [ADR-003](../../DECISIONS.md), [next task](../../NEXT_TASK.md) and the
[physical test plan](../../P01_PLATFORM_TEST_PLAN.md) for the scoped adaptation.
