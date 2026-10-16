# User guide

Current packages are review candidates. Production use awaits the exact signing,
independent review and real-device checks listed in [release status](P18_RELEASE.md).
Use only the independently verified service address and approved client. A valid
login gives account access; local unlock and trusted-device approval give content
access. An administrator has no master content decryption key.

## Install, register and unlock

On Windows11 x64, verify the publisher/signature and exact installer checksum
through the trusted release channel, then run the single setup executable as the
current user. It installs the required runtime and notices; you do not assemble
developer tools. The present unsigned review installer has no production signer.
Choose the independently obtained service trust configuration in the native
dialog. Keep the encrypted profile at
`%LOCALAPPDATA%\org.anynote.desktop\profiles`; it contains recoverable local work.

On iPhone, open the trusted app HTTPS origin in Safari and choose Share → Add to
Home Screen. Launch that installed app for the intended offline/file workflow.
Do not bypass certificate warnings. Automated WebKit evidence does not establish
that the physical iPhone1GB Files workflow is ready. Trusted hosting is still a
pending owner step. [PWA notes](P15_IPHONE.md) explain storage/lifecycle limits.

Use a valid single-use account invitation and your supported passkey. Save the
account recovery kit privately when creating the identity. Use a strong local
unlock phrase where hardware/PRF protection is unavailable. Never send the phrase,
passkey material, recovery secret, enrollment QR or export kit to support/chat.
Provider availability alone does not prove TPM binding or fresh Hello gating.

## Save, synchronize and share

Choose a group, thread and note. Local save acknowledges an encrypted draft;
publication and server confirmation are separate. On Windows Ctrl+S saves,
Ctrl+Shift+S publishes and Ctrl+Shift+L locks. Offline drafts remain private until
authorized publication. A pending/unknown acknowledgement must be reconciled;
do not clear the profile or repeatedly recreate the same work. Resolve conflicting
heads explicitly after inspecting both versions.

For a new device, sign in separately, compare the account and full fingerprints
through a trusted channel, then approve and confirm the expiring QR ceremony on
both devices. Never approve an unexpected request. A QR is a one-time private
channel; it is not a substitute for comparing identity. Expired/interrupted
pairing may require a new ceremony while the existing encrypted data is retained.

Before inviting a reader/editor, verify their independent account card/root
fingerprint and the exact role. Admission includes **all retained history and
trash**, not only current notes. The invitation must be accepted and the required
keys committed before access becomes active. Copying selected private material
to a shared destination creates fresh objects/keys after you review the audience;
it does not silently expose the private group's whole history.

Readers read; editors publish; the owner controls membership/ownership. Ownership
transfer needs both owners' consent. Resolve owned shared groups before closing
an account. Archive makes content read-only while required security maintenance
remains possible. Removing a member/device immediately blocks new server access;
finish the requested rekey before new shared writes. Previously downloaded copies
and old readable keys cannot be remotely erased. A stale isolated client may not
yet know about a revoke; do not promise global immediate secrecy.

## Files, storage and updates

The original-file limit is1,000,000,000 bytes. Use an unchanged selected source
when resuming a transfer. If it changed, follow the fresh attempt/re-encryption
flow; never reuse an old file version for new bytes. Keep the source until commit
and attachment confirmation. Failed storage/role/quota checks must preserve the
draft; reconnect/reselect/reconcile through the visible workflow. A pause or
background event does not mean completion. Keep iPhone exports in the foreground
and verify the final file in Files once the physical workflow is validated.

Cache cleanup removes replaceable downloads, not server notes or unsent drafts.
Do not clear site data, uninstall browser profiles or delete the Windows profile
to repair an error: that may destroy the only unsent copy. Export independently
first. Search and preview are local; unsupported/unsafe documents require an
explicit save/open decision outside the protected app.

Install updates through the verified publisher channel. Windows checks the fixed
operator policy, signed payload/claims and downgrade protection; PWA updates may
wait for a safe activation point. Save work and keep encrypted profiles/outbox
through updates. Do not downgrade the executable/schema or restore an old DB
over current service state. A failed update is a support event, not permission to
delete data or disable signature verification.

## Keep recovery material and export safely

An account root recovery kit and a portable export kit serve different purposes.
Store independent offline copies separately from the device/service, test them
in the bounded offline recovery flow, and restrict who can read them. Anyone with
the secret may gain the corresponding recovery authority. Losing every copy of
the required secret can make content unrecoverable; an operator cannot reset a
password to decrypt it. Recovery never grants another group's ownership.

For an independently usable content backup, export the selected/account content
as an encrypted portable archive and save its **separate export kit only after
completion**. Keep the archive and kit in separate protected locations. Include
retained history/trash only after reviewing the selection and audience. Verify
the archive offline before relying on it. For shared/rotated history, use this
portable export and its kit; the bounded server-backup/root-kit reader covers
only private epoch-zero groups with independently retained checkpoints.

Explicit plaintext export/recovery writes readable final files outside AnyNote.
Other apps, cloud folders, backups, indexing, clipboard and OS remnants may retain
them. Removing access later does not revoke these files. Choose a new private
destination and confirm this deliberate handoff; do not export into a public or
automatically synchronized folder unless you intend that disclosure.

After a service restore, stop ordinary work at `RESTORE_QUARANTINE`. Keep encrypted
drafts/outbox and independent checkpoints. The operator keeps restored credentials
disabled. Verify authorized content offline, then explicitly import/copy it into
a verified fresh identity/group with fresh keys. Restoring ciphertext is not
restoring current membership or making an old session trustworthy. See
[portable recovery](P13_CONTENT.md) and [operator handoff](OPERATOR_HANDOFF.md).

## Language and support

The application supports English, Russian and Arabic. Choose the language in the
app; Arabic layout follows the existing RTL handling. Verify displayed audience,
fingerprint, error and destructive-action confirmation in the selected language.
The linked P18 file includes Unicode/RTL text; existing localization/WebKit tests
are software evidence, not a claim that a human translated/reviewed every phrase.

For a failure, record the app version/source identifier, operating system, time,
visible bounded error code and whether work is saved/pending/unknown. Send only
these nonsecret facts through the owner's established support channel. Never
send private note bodies, filenames, cookies, tokens, phrases, full diagnostic DBs
or recovery/export kits. For unexpected device prompts, integrity errors or a
suspected malicious app update, lock, stop publication and contact the owner via
an independent trusted channel. Support must preserve evidence and local work.
