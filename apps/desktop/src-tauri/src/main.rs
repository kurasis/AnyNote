#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use anynote_windows_native::{
    bridge::Assets,
    host::{Binding, Host, Request, Service},
    selection::Source,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tauri::{Emitter, Manager};
use zeroize::Zeroize;
struct State {
    host: Mutex<Option<Arc<Host>>>,
    root: PathBuf,
    modal: AtomicUsize,
    generation: Arc<AtomicU64>,
}
struct Modal(Arc<State>);
impl Drop for Modal {
    fn drop(&mut self) {
        self.0.modal.fetch_sub(1, Ordering::SeqCst);
    }
}
impl State {
    fn modal(self: &Arc<Self>) -> Modal {
        self.modal.fetch_add(1, Ordering::SeqCst);
        Modal(self.clone())
    }
    fn host(&self) -> Result<Arc<Host>, String> {
        self.host
            .lock()
            .map_err(|_| "HOST_BUSY")?
            .clone()
            .ok_or("PROFILE_REQUIRED".into())
    }
    fn lock(&self) {
        if let Ok(h) = self.host() {
            h.lock();
        }
    }
}
fn binding(window: &tauri::WebviewWindow) -> Result<Binding, String> {
    let origin = window
        .url()
        .map_err(|_| "IPC_SCOPE_DENIED")?
        .origin()
        .ascii_serialization();
    #[cfg(windows)]
    let hwnd = window.hwnd().map_err(|_| "INVALID_NATIVE_WINDOW")?.0 as usize;
    #[cfg(not(windows))]
    let hwnd = 0;
    let b = Binding {
        label: window.label().into(),
        origin,
        hwnd,
    };
    b.validate().map_err(|e| e.0.to_owned())?;
    Ok(b)
}
#[tauri::command]
async fn product(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Arc<State>>,
    generation: u64,
    request: Value,
) -> Result<Value, String> {
    let b = binding(&window)?;
    let host = state.host()?;
    let request: Request = serde_json::from_value(request).map_err(|_| "INVALID_REQUEST")?;
    let hello = matches!(&request, Request::UnlockHello {});
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _modal = hello.then(|| state.modal());
        host.execute(&b, generation, request)
            .map_err(|e| e.0.into())
    })
    .await
    .map_err(|_| "HOST_UNAVAILABLE")?
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum ProfileCommand {
    List {},
    Open { profile_id: String },
    Create { phrase: String, hello: bool },
}
#[tauri::command]
async fn profile(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Arc<State>>,
    request: Value,
) -> Result<Value, String> {
    let b = binding(&window)?;
    let state = state.inner().clone();
    let request: ProfileCommand = serde_json::from_value(request).map_err(|_| "INVALID_REQUEST")?;
    tauri::async_runtime::spawn_blocking(move||{match request{
  ProfileCommand::List{}=>{let mut rows=Vec::new();for entry in std::fs::read_dir(&state.root).map_err(|_|"STORAGE_UNAVAILABLE")?{let entry=entry.map_err(|_|"STORAGE_UNAVAILABLE")?;let p=entry.path().join("profile.json");if entry.file_type().map_err(|_|"STORAGE_UNAVAILABLE")?.is_dir()&&p.exists(){let bytes=std::fs::read(p).map_err(|_|"STORAGE_UNAVAILABLE")?;let value=anynote_crypto_core::codec::strict(&bytes,65536).map_err(|_|"INVALID_PROFILE")?;rows.push(json!({"profile_id":entry.file_name().to_string_lossy(),"account_id":value["scope"]["account_id"],"issuer":value["service"]["issuer"]}));}}Ok(json!({"items":rows}))},
  ProfileCommand::Open{profile_id}=>{if profile_id.len()!=22||!profile_id.bytes().all(|c|c.is_ascii_alphanumeric()||b"_-".contains(&c)){return Err("INVALID_PROFILE".into());}state.lock();let mut host=Host::open(&state.root.join(profile_id)).map_err(|e|e.0)?;host.generation=state.generation.clone();state.generation.fetch_add(1,Ordering::SeqCst);let host=Arc::new(host);*state.host.lock().map_err(|_|"HOST_BUSY")?=Some(host);Ok(json!({"state":"locked"}))},
  ProfileCommand::Create{mut phrase,hello}=>{let _modal=state.modal();let selected=rfd::FileDialog::new().set_parent(&window).add_filter("Trusted public service configuration",&["json"]).pick_file().ok_or("CANCELLED")?;let mut source=Source::open(&selected,65536).map_err(|e|e.0)?;let bytes=source.small(65536).map_err(|e|e.0)?;let service:Service=serde_json::from_value(anynote_crypto_core::codec::strict(&bytes,65536).map_err(|e|e.0)?).map_err(|_|"INVALID_SERVICE_CONFIGURATION")?;
    let profile_id=anynote_crypto_core::crypto::b64(&anynote_crypto_core::crypto::random_key().map_err(|e|e.0)?[..16]);let result=Host::create(&state.root.join(&profile_id),service,&phrase,hello,b.hwnd);phrase.zeroize();let mut host=result.map_err(|e|e.0)?;state.lock();host.generation=state.generation.clone();state.generation.fetch_add(1,Ordering::SeqCst);let host=Arc::new(host);*state.host.lock().map_err(|_|"HOST_BUSY")?=Some(host);Ok(json!({"profile_id":profile_id,"state":"locked"}))}
 }}).await.map_err(|_|"HOST_UNAVAILABLE")?
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum FileCommand {
    Upload {
        group_id: String,
        resume: Option<String>,
    },
    Download {
        group_id: String,
        file_version_id: String,
        offline: bool,
    },
    Export {
        group_ids: Vec<String>,
        history: bool,
        trash: bool,
        kib_per_second: u64,
    },
    SaveKit {
        export_id: String,
    },
    InspectImport {
        destination: Option<String>,
        resume: Option<String>,
    },
    ConfirmImport {
        import_id: String,
        audience_digest: String,
    },
    Preview {
        group_id: String,
        file_version_id: String,
    },
}
fn assets(app: &tauri::AppHandle) -> Result<(PathBuf, PathBuf, Value), String> {
    let root = app
        .path()
        .resource_dir()
        .map_err(|_| "RUNTIME_UNAVAILABLE")?
        .join("resources");
    let manifest = anynote_crypto_core::codec::strict(
        include_bytes!("../resources/runtime-manifest.json"),
        65536,
    )
    .map_err(|_| "RUNTIME_INTEGRITY_FAILURE")?;
    Ok((root.join("node.exe"), root.join("custody.mjs"), manifest))
}
#[tauri::command]
async fn file_job(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Arc<State>>,
    generation: u64,
    request: Value,
) -> Result<Value, String> {
    binding(&window)?;
    let state = state.inner().clone();
    let host = state.host()?;
    let app = window.app_handle().clone();
    let request: FileCommand = serde_json::from_value(request).map_err(|_| "INVALID_REQUEST")?;
    tauri::async_runtime::spawn_blocking(move||{host.capability(generation).map_err(|e|e.0)?;match request{
  FileCommand::Upload{group_id,resume}=>{let _modal=state.modal();let selected=rfd::FileDialog::new().set_parent(&window).pick_file().ok_or("CANCELLED")?;let source=Source::open(&selected,1000000000).map_err(|e|e.0)?;let job=host.start_upload(generation,group_id,source,resume).map_err(|e|e.0)?;Ok(json!({"job_id":job}))},
  FileCommand::Download{group_id,file_version_id,offline}=>{let _modal=state.modal();let selected=rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-file.bin").save_file().ok_or("CANCELLED")?;let job=host.start_download(generation,group_id,file_version_id,&selected,offline).map_err(|e|e.0)?;Ok(json!({"job_id":job}))},
  FileCommand::Export{group_ids,history,trash,kib_per_second}=>{let plan=host.prepare_export(generation,&group_ids,history,trash,kib_per_second).map_err(|e|e.0)?;let _modal=state.modal();let selected=rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-export.age").save_file().ok_or("CANCELLED")?;let(node,script,manifest)=assets(&app)?;let job=host.jobs.start(generation).map_err(|e|e.0)?;let id=job.id.clone();std::thread::spawn(move||{let a=Assets{node:&node,script:&script,node_sha:manifest["node_sha256"].as_str().unwrap_or(""),script_sha:manifest["script_sha256"].as_str().unwrap_or("")};let r=host.export_archive(generation,plan,&selected,&a,job.clone());job.finish(r);});Ok(json!({"job_id":id}))},
  FileCommand::SaveKit{export_id}=>{let _modal=state.modal();let selected=rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-recovery-kit.json").save_file().ok_or("CANCELLED")?;host.save_kit(generation,&export_id,&selected).map_err(|e|e.0.into())},
  FileCommand::InspectImport{destination,resume}=>{let _modal=state.modal();let selected=rfd::FileDialog::new().set_parent(&window).add_filter("Encrypted archive",&["age"]).pick_file().ok_or("CANCELLED")?;let source=Source::open(&selected,116010000000).map_err(|e|e.0)?;let selected=rfd::FileDialog::new().set_parent(&window).add_filter("Separate recovery kit",&["json"]).pick_file().ok_or("CANCELLED")?;let mut selected=Source::open(&selected,65536).map_err(|e|e.0)?;let mut kit=anynote_crypto_core::codec::strict(&selected.small(65536).map_err(|e|e.0)?,65536).map_err(|e|e.0)?;let(node,script,manifest)=assets(&app)?;let a=Assets{node:&node,script:&script,node_sha:manifest["node_sha256"].as_str().unwrap_or(""),script_sha:manifest["script_sha256"].as_str().unwrap_or("")};let result=host.inspect_import(generation,source,kit.take(),destination.as_deref(),resume.as_deref(),&a);result.map_err(|e|e.0.into())},
  FileCommand::ConfirmImport{import_id,audience_digest}=>Ok(json!({"job_id":host.start_import(generation,&import_id,&audience_digest).map_err(|e|e.0)?})),
  FileCommand::Preview{group_id,file_version_id}=>{let _=host.read_preview(generation,&group_id,&file_version_id).map_err(|e|e.0)?;Err("SAFE_DOWNLOAD_REQUIRED".into())}
 }}).await.map_err(|_|"HOST_UNAVAILABLE")?
}
fn main() {
    tauri::Builder::default()
        .plugin(
            tauri::plugin::Builder::new("navigation-boundary")
                .on_navigation(|_, url| {
                    ["http://tauri.localhost", "tauri://localhost"]
                        .contains(&url.origin().ascii_serialization().as_str())
                        && url.username().is_empty()
                        && url.password().is_none()
                })
                .build(),
        )
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            product, profile, file_job, open_link, update
        ])
        .setup(|app| {
            let root = app.path().app_local_data_dir()?.join("profiles");
            std::fs::create_dir_all(&root)?;
            let state = Arc::new(State {
                host: Mutex::new(None),
                root,
                modal: AtomicUsize::new(0),
                generation: Arc::new(AtomicU64::new(0)),
            });
            app.manage(state.clone());
            let window = app
                .get_webview_window("main")
                .ok_or("main window missing")?;
            #[cfg(windows)]
            windows::attach(&window, state.clone())?;
            let handle = app.handle().clone();
            window.on_window_event(move |event| match event {
                tauri::WindowEvent::Focused(false) if state.modal.load(Ordering::SeqCst) == 0 => {
                    state.lock();
                    let _ = handle.emit("vault-locked", json!({"reason":"background"}));
                }
                tauri::WindowEvent::CloseRequested { .. } => state.lock(),
                _ => {}
            });
            Ok(())
        })
        .on_webview_event(|window, event| {
            if matches!(event, tauri::WebviewEvent::DragDrop(_)) {
                let _ = window;
            }
        })
        .run(tauri::generate_context!())
        .expect("AnyNote native host failed");
}
#[cfg(windows)]
mod windows;

#[tauri::command]
fn open_link(window: tauri::WebviewWindow, url: String) -> Result<(), String> {
    binding(&window)?;
    let parsed = tauri::Url::parse(&url).map_err(|_| "INVALID_LINK")?;
    if url.len() > 4096
        || !matches!(parsed.scheme(), "https" | "http")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("INVALID_LINK".into());
    }
    use tauri_plugin_opener::OpenerExt;
    window
        .app_handle()
        .opener()
        .open_url(url, None::<&str>)
        .map_err(|_| "SYSTEM_BROWSER_UNAVAILABLE".into())
}

#[tauri::command]
async fn update(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Arc<State>>,
    generation: u64,
    install: bool,
    confirmed: bool,
) -> Result<Value, String> {
    binding(&window)?;
    let host = state.host()?;
    host.capability(generation).map_err(|e| e.0)?;
    let bytes = std::fs::read(
        state
            .root
            .parent()
            .ok_or("STORAGE_UNAVAILABLE")?
            .join("update-policy.json"),
    )
    .map_err(|_| "UPDATE_TRUST_NOT_CONFIGURED")?;
    let policy: anynote_windows_native::updates::UpdatePolicy =
        serde_json::from_value(anynote_crypto_core::codec::strict(&bytes, 65536).map_err(|e| e.0)?)
            .map_err(|_| "INVALID_UPDATE_POLICY")?;
    policy.validate().map_err(|e| e.0)?;
    use tauri_plugin_updater::UpdaterExt;
    let updater = window
        .app_handle()
        .updater_builder()
        .pubkey(policy.public_key.clone())
        .endpoints(vec![
            tauri::Url::parse(&policy.endpoint).map_err(|_| "INVALID_UPDATE_POLICY")?,
        ])
        .map_err(|_| "INVALID_UPDATE_POLICY")?
        .build()
        .map_err(|_| "INVALID_UPDATE_POLICY")?;
    let Some(next) = updater.check().await.map_err(|_| "UPDATE_UNAVAILABLE")? else {
        return Ok(json!({"state":"CURRENT"}));
    };
    policy
        .version("0.14.0", &next.version, "windows-x86_64", &policy.channel)
        .map_err(|e| e.0)?;
    if !install {
        return Ok(
            json!({"state":"AVAILABLE","version":next.version,"channel":policy.channel,"signature_required":true}),
        );
    }
    if !confirmed {
        return Err("CONFIRMATION_REQUIRED".into());
    }
    let bytes = next
        .download(|_, _| {}, || {})
        .await
        .map_err(|_| "UPDATE_INTEGRITY_FAILURE")?;
    host.capability(generation).map_err(|e| e.0)?;
    state.lock();
    next.install(bytes).map_err(|_| "UPDATE_INSTALL_FAILED")?;
    Ok(json!({"state":"INSTALLING"}))
}
