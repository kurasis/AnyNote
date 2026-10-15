# Windows desktop application

P14 software acceptance is recorded in docs/evidence/p14 and TEST_EVIDENCE.md.
P14_DEVELOPMENT.md retains earlier development observations. Actual installed
Windows/WebView2 and gigabyte/update tests passed at the recorded exact source.
Production Authenticode/updater credentials and physical
Hello/TPM/session/suspend acceptance remain separate requirements.

## Installation and local custody

The owner receives one NSIS setup executable. It installs AnyNote, its pinned
trusted streaming runtime, preview workers, licenses, SBOM and source-commit
notice. It automatically bootstraps Microsoft's maintained WebView2 Evergreen
runtime if missing. Installation is current-user; the owner does not assemble
Node, Rust, age or separate diagnostic utilities. Windows 11 x64 is the target.
A downloaded unsigned development installer is not a production-signed release.

Local profiles are under `%LOCALAPPDATA%\org.anynote.desktop\profiles`. Device and
group keys, native OAuth credentials, local content, drafts, immutable attempts,
source proofs and recovery journals stay in native protected custody. The UI has
five typed commands and event subscription. It has no general path, SQL, HTTP,
key export or signing operation. A preview has no native command permissions.

Choose a saved profile, or select an independently obtained public service trust
configuration through the native dialog. Complete local unlock separately from
system-browser login and device enrollment. Interrupted profile setup resumes the
same prepared identity. Phrase fallback must be strong; provider availability is
not proof of TPM binding or fresh Hello authorization. See the retained
[Windows Hello handoff](reference/passkeylocal/WINDOWS_HELLO_DEVELOPER_HANDOFF.md.txt).

## Notes, groups and access

The three panes select a group, thread and content. Local encrypted save,
publication, unknown receipt and conflict are distinct. Ctrl+S saves locally;
Ctrl+Shift+S publishes; Ctrl+Shift+L locks. Checklists and canonical tags are
editable. Unresolved heads remain independently inspectable and explicit conflict
resolution requires native confirmation. Archive/trash and restoring a prior
version preserve signed ancestry. Search authenticates source content; rebuild
refreshes the encrypted derived index.

Offline view reads authenticated local records. Cache removal applies only to
replaceable downloaded ciphertext. It does not discard sources, drafts, attempts
or recovery journals. Role loss blocks publication while retaining work. Recover
a draft into an owned private thread, or create a separate private-to-shared
copy after reviewing the actual current audience in a native confirmation.
Group/thread destination pickers show verified titles rather than requiring IDs.

Device enrollment supports both QR directions. Compare the account, full device
fingerprint and expiry on both screens before approving and confirming. PNG save
is an explicit private-channel handoff of a one-time enrollment channel; it is
not an export of device/group/root private keys. Prepared signed requests can be
retried; a closed ephemeral channel requires a fresh enrollment ceremony while
old encrypted data is retained. Revocation confirms descendants against an exact
verified roster head. Group key delivery is recipient-bound.

Independent public account/group cards establish trust before invitations. Member
admission, role changes, removal, history checkpoints, epochs and joint ownership
follow the maintained signed protocols. Ownership consent is independently
cosigned and retained before any optional public-document save is attempted.

## Files, recovery and lifecycle

Native Open/Save dialogs select checked handles; the renderer never supplies a
raw path. File jobs are bounded, generation-bound, cancellable and resumable with
an unchanged selected source. A copied selected file gets fresh IDs and keys;
the original transfer remains available. Current policy is checked again before
publication. Unknown acknowledgements reconcile the existing immutable attempt.

Export captures a selected or whole-account snapshot, estimates space/time and
honors its maximum 24-hour lease. Output is standard streaming age with a separate
recovery kit. Only after authenticated EOF and durable output can the kit be
saved separately. An interrupted final output can be recovered from its retained
encrypted stage. No plaintext archive/key staging directory is created.

Import validates the complete archive offline before destination mutation, then
asks for current destination confirmation. New private recovery is the default.
It uses fresh IDs, DEKs and authorship; the original archive retains provenance.
Source-group metadata is preserved in named threads, missing source threads get
stable placeholders, and attachments map to newly authenticated destination files.
Protected aliases and exact receipts survive pause/lock/reselect. Expired or
obsolete-epoch uploads are reconciled and burned before fresh preparation.

Previews use isolated windows and existing bounded text/image/PDF workers. Active
HTML, remote images, generic IPC, foreign navigation, popups and unsolicited
browser downloads are denied. Unsupported/oversized previews use explicit Save.
Copy saved text is an explicit system-clipboard handoff: other apps can read it.
A 30-second timer and lock cleanup attempt to remove only AnyNote's unchanged
clipboard value; another application's later copy is retained. OS handoffs and
perfect memory erasure cannot be revoked or guaranteed.

Main-HWND session/power hooks invalidate native generation before UI notification.
Background, idle, scope change and lock close sensitive previews and fence late
responses. File/system dialogs have a scoped modal guard, then recheck generation
and foreground. Hosted software messages do not prove physical Win+L/suspend or
Hello/TPM behavior.

Bounds include 1,000,000,000 bytes per original file, 16 MiB IPC frames, at most
four queued helper frames plus one fixed frame buffer, 16 MiB preview input,
64 MiB portable metadata and the maintained P13 archive/item/selection limits.
Native protected record/journal and report limits may require smaller selections.
Resource exhaustion fails closed and preserves recovery sources. Only the actual
recorded sizes and process measurements may be advertised as tested; arbitrary
100 GB recovery and the initial incremental-memory targets are not implied.

## Build and verification

On Windows with maintained MSVC tools, activate Rust 1.99 and Node 24.21. Install
frozen npm dependencies for protocol, content-browser and desktop, then run:

```powershell
npm --prefix apps/desktop run build
python apps/desktop/prepare-runtime.py
python scripts/p14-dependencies.py --stage
python scripts/check-p14.py
cargo test --manifest-path packages/windows-native/Cargo.toml --locked -j 4 -- --test-threads=1
npm --prefix apps/desktop run tauri -- build --ci -- --locked -j 4
```

The single owner setup is in `apps/desktop/src-tauri/target/release/bundle/nsis`.
The owner build removes WebView2 debugging environment overrides. A separately
instrumented CI host permits local CDP for actual WebView2/UI acceptance while
retaining native custody, TLS, origin and command checks. It is never the owner
installer. CI uses disposable marked accounts, private test TLS and real API/SQL.
The production backend remains Linux/Nginx/PHP-FPM/MariaDB. Its strict directory
fsync remains mandatory; the Windows-only synthetic backend additionally flushes
its own volume through a pinned real OS helper rather than faking PHP directory
fsync support. The CI volume helper is not part of the owner application.

The workflow exercises actual gigabyte transfer/export/offline recovery/import,
native dialogs, three-pane/keyboard edits, preview/IPC/navigation denials,
clipboard, encrypted SQL/cache, installer rerun, process restart and signed test
upgrades. Exact-source reports bind the raw receipts and installer bytes to all
tracked inputs. All 24 inherited checks remain required alongside host acceptance.

See [update signing requirements](P14_UPDATE_SIGNING.md). Ephemeral CI signatures
exercise HTTPS metadata and payload tampering, real candidate installation and
retained encrypted data. They do not establish a production signing identity.
Never place an updater private key in the app, API host, source or artifacts.
