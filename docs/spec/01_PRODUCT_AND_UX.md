# Product, Functional Scope, and UX

## 1. Intended experience

The service is a compact personal knowledge and document vault with small-group collaboration. It is not a public social network, Slack replacement, or enterprise content-management platform. Optimize for quickly saving a note or file, finding it later, moving between Windows and iPhone, and understanding who can read it.

Each account has a Personal section and a Shared section. A group is the first-release access boundary. A thread has a title, chronological entries, and an optional pinned summary entry. Entries may contain Markdown text, checklist data, and attachments. The group's Files tab is a view of existing attachments, not a second physical copy.

## 2. Core workflows

### First account

An operator creates a one-time bootstrap invitation. The first user registers a passkey, initializes account identity and device keys locally, creates and verifies a recovery kit, and creates a private group. Server-operator privileges are assigned separately from content-group ownership. Close the bootstrap route after use.

### Additional account

An administrator issues a single-use invitation with a 48-hour default expiry. It authorizes account creation, not access to any existing group. The recipient creates an independent identity and recovery kit. A group owner subsequently invites that account to a shared group.

### Add a device

Sign in on the new device, generate device keys there, start enrollment, and approve from a trusted device after authenticated QR/SAS verification. Display devices, origin, account, expiry, and what is being granted. Device approval and a successful login are separate events.

### Capture information

Create or select a group and thread, type an entry, attach files, and see durable local-save status followed by server-sync status. Uploading a file MUST NOT block saving unrelated text. An attachment in progress has an explicit pending state and is not presented as readable by other users.

### Share safely

Select an account by its verified identity, show its role and full-history policy, confirm membership, and distribute encrypted group-key envelopes. A private group is never made shared by a casual toggle. The safe action is “Create shared copy,” with explicit selection of entries, files, and whether retained history is included; default to current selected content only.

## 3. First-release features

| Area | Required behavior |
| --- | --- |
| Organization | Create/rename/archive groups and threads; reorder groups locally or via encrypted account preferences |
| Entries | Markdown editor, plain-text paste, code blocks, links, checklists, explicit save status |
| Thread summary | Pin one summary entry; additional entry pins allowed within documented limits |
| Attachments | Multi-select, Windows drag-and-drop, progress, cancellation, resume, download/export |
| Navigation | Recent items, favorites, unread shared activity, search, breadcrumbs on mobile |
| Search | Local full-text search over loaded titles/body/tags; filter group, type, and date |
| Versions | Author, revision history, compare text where practical, restore as a new revision |
| Deletion | Trash, restore, retention timer, owner-controlled permanent purge |
| Offline | Notes and selected files; readable local content after unlock; encrypted durable outbox |
| Sharing | Owner/editor/reader; membership changes; full-history invitation warning |
| Account security | Passkeys, device list, session list, recovery status, device revoke |
| Privacy | Auto-lock, neutral notifications, explicit plaintext export, local cache controls |
| Administration | Invite accounts, disable accounts, manage limits, inspect content-free health |

OCR, external share links, AI analysis, realtime character-by-character collaboration, plugins, federation, public registration, arbitrary HTML notes, media transcoding, and native iOS are deferred.

## 4. Roles

| Action | Owner | Editor | Reader |
| --- | --- | --- | --- |
| Read/search/download authorized content | Yes | Yes | Yes |
| Create/edit entries and upload files | Yes | Yes | No |
| Soft-delete/restore entries | Yes | Yes | No |
| Rename/archive threads | Yes | Yes | No |
| Change group title/settings or archive group | Yes | No | No |
| Invite/remove accounts/change roles | Yes | No | No |
| Transfer group ownership/permanently delete group | Yes | No | No |
| Maintain key envelopes for one's own verified devices | Yes | Yes | Yes |
| Execute mandatory roster-only rekey with the exact verified recipient set | Yes | Yes | Yes |
| Request optional group rekey without membership changes | Yes | Yes | No |

Exactly one owner per group in v1. Ownership transfer requires both accounts' signed consent and recent authentication. A group cannot be left without an owner. Reader access cannot prevent screenshots, exports, or copying.

## 5. Interface layout

Windows: three panes for groups, threads, and thread content, with resizable widths and keyboard navigation. iPhone: stacked screens, safe-area support, visible Back navigation, usable attachment actions, and no hover-only controls. Use a restrained document-oriented design, light/dark themes, and accessible focus indicators. Avoid embedding protocol terminology in ordinary screens.

Required screens: sign-in; onboarding/recovery; locked vault; enrollment; group/thread/entry; files; search; versions; trash; transfers; members; devices/sessions; storage; export/import; admin; diagnostics. Notifications and lock-screen views MUST NOT contain decrypted group names, entry text, or filenames.

The security state of an item must be understandable: private/shared, participant count, verified identity warning, readonly, archived, unavailable key, sync conflict, or integrity failure. Integrity failures must never silently render the unverified payload.

## 6. Save and failure states

Use separate labels: “Saving on this device,” “Saved on this device,” “Syncing,” “Synced,” and “Needs attention.” Only claim local durability after transaction/flush completion and server durability after committed acknowledgement. Offline is a normal state, not a repeated error toast.

Provide actionable messages for: quota full; local storage unavailable; storage eviction; expired invitation; key not yet delivered; stale membership; revoked device; invalid signature; unsupported encryption version; conflicting edit; upload source lost; server unavailable. Include retry/re-enroll/export-draft actions where appropriate. Never suggest disabling encryption to recover from an error.

## 7. Privacy and retention UX

Show storage usage split into current content, retained versions, trash, and pending reservations. Explain that shared content counts once globally. Deletion enters 30-day trash by default. Restoring a past revision creates a new revision, preserving auditability.

On plaintext export, state that the resulting file is readable outside the vault. No forced multi-click warning for every ordinary download; one clear confirmation when beginning an export or enabling automatic external-open behavior is sufficient. Never export silently for thumbnail generation.

Favorites, read markers, personal ordering, and explicitly synchronized drafts are private to the account and synchronized as E2EE account-private records. Routine autosave drafts remain encrypted locally; publishing retires the private draft after verified commit unless the user explicitly keeps a copy. This avoids unexpected duplicate retention of deleted shared content. Other members do not see whether someone read an entry in v1. An encrypted account-private settings namespace is a hidden private group using the same key machinery.

## 8. Performance and accessibility targets

Use virtualized long lists. Avoid scanning all 100 GB to render a group. Display metadata first; fetch attachment bytes on demand. Editing must remain responsive during encryption. Provide keyboard-only workflows on Windows, screen-reader labels, adequate contrast, reduced-motion support, and mobile touch targets of at least approximately 44 CSS pixels for primary actions.

UI strings must be internationalization-ready. Include English and Russian for the initial user-facing interface; internal identifiers, API contracts, and developer documentation remain English. Dates display in the user's locale/timezone; canonical ordering uses server sequence numbers, not displayed timestamps.

## 9. Onboarding and audience safeguards

Untrusted installations see only minimal account/enrollment/recovery state. Group invitations require acceptance by the invited account. Private group ownership cannot be transferred through the ordinary shared-group ownership action. Pending file publication and orphan recovery are visible workflows, not hidden technical failures. A source draft is never erased simply because a server reports device revocation.
