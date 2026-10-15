# Native Windows application — P14 development

This is the application host, distinct from the P01 owner kit and the age CI
interop harness. P14 software acceptance is recorded in docs/evidence/p14.
Builds are unsigned development candidates; physical/qualified gates and
production signing remain open.

The single NSIS setup executable contains the Rust application, the pinned Node
runtime used for standard-age streaming, the compiled helper and its licenses.
The installer installs WebView2 automatically when it is missing. Users do not
assemble external executables or copy private keys into the renderer.

The main window sends strictly decoded product commands. Custody, signing,
authority, credentials, dialogs and large-file jobs stay native. The trusted
portable helper uses bounded anonymous pipes, no network, no selected paths,
no device/group/root keys and hash-verified assets. Imports validate before
destination mutation and create fresh destination custody.

Build with the frozen app dependencies, Rust 1.99.0 and Node 24.21.0:

```powershell
npm --prefix packages/protocol ci --ignore-scripts --no-audit --no-fund
npm --prefix packages/content-browser ci --ignore-scripts --no-audit --no-fund
npm --prefix apps/desktop ci --no-audit --no-fund
npm --prefix apps/desktop run build
python apps/desktop/prepare-runtime.py
python scripts/p14-dependencies.py --stage
npm --prefix apps/desktop run tauri -- build --ci -- --locked -j 4
```

The HTTPS issuer, app and independent public pins come from a native-selected
public service configuration. They are fixed per profile. Passwords, bearer
credentials and private keys do not belong in this public file.

P15 is the next batch in `docs/NEXT_TASK.md`. The P14 development log preserves
historical observations; exact-source acceptance has its own recorded scope.
