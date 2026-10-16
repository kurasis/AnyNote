# P15 postmerge lifecycle follow-up

The ordinary push cohort on merged main
`b1832ce0ae98bc7e1ca2bb567cad20b3c7303432` completed with 25 PASS and
two FAIL. This does not relabel the separately passing 27-job premerge head
`d2aeff8a6a6ca8e0166f14c32ef4b13d55142eec`. Original cohort, exact public
PWA report, failure log excerpts and GitHub artifact metadata are retained here.

The PWA completed the genuine P12 gigabyte and the early one-byte quota fault,
then timed out unlocking before its P15 workflow. The only captured Worker denial
was `notes.group / VAULT_LOCKED / explicit`; P15 was PENDING, not PASS.
Group status/list and shared proof requests now retain the UI generation across
network awaits before entering custody or updating maps. The added actual-browser
regression delays genuine authenticated group/list requests across explicit lock,
queues a new unlock and requires that neither response reenter locked custody or
relock that unlock. It never synthesizes API or crypto results.

The Windows job exited 1 during `signed-test-upgrade` without a JavaScript
exception or completed WebView receipt. Its exact death cause was not captured.
The test repeatedly opened the installed executable to hash it while the pinned
NSIS installer could register that executable with Windows Restart Manager and
force resource users to exit. The pinned CLI 2.12.2 template's
`CheckIfAppIsRunning` uses RmRegisterResources/RmGetList/RmShutdown. The observer
now polls directory metadata without an executable read handle, then retains
full byte/version, restart, draft and immutable-outbox checks after replacement.
An early read-only Windows regression holds a disposable file in a separate Node
process and queries the real Restart Manager list, then closes it and requires
metadata polling to leave the observer unregistered. It never invokes shutdown.
That proves or rejects the handle mechanism; it cannot retrospectively supply a
missing trace of the old process death.

Local results before commit: six CDP/frame/metadata checks PASS, Windows-only
Restart Manager check NOT RUN on Linux; seven PWA policy/localization checks,
actual strict-CSP bundle and unchanged 179-file baseline PASS. No dependency,
frozen format, production guard or timeout is relaxed. Clean exact-head normal
CI, raw artifact/source audits and guarded merge have separate final receipts
and must not be inferred from these local checks. The exact-source public final
archive will be linked from the completed PR.

P16 remains next. Physical G1/U11/U12/PRF/Hello/TPM, qualified G2/G3, production
signing/deployment, unresolved memory targets and arbitrary 100 GB remain open.
Published environment configuration and observed fresh-task restoration remain
separate facts.
