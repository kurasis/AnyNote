#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod clipboard;
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
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tauri::{Emitter, Manager};

struct State {
    host: Mutex<Option<Arc<Host>>>,
    root: PathBuf,
    modal: AtomicUsize,
    updating: std::sync::atomic::AtomicBool,
    generation: Arc<AtomicU64>,
    app: OnceLock<tauri::AppHandle>,
}
struct Modal(Arc<State>);
impl Drop for Modal {
    fn drop(&mut self) {
        if self.0.modal.fetch_sub(1, Ordering::SeqCst) == 1 && !self.0.owns_foreground() {
            self.0.lock();
            if let Some(app) = self.0.app.get() {
                let _ = app.emit(
                    "vault-locked",
                    json!({"reason":"background-after-system-dialog"}),
                );
            }
        }
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
    fn mask(&self) {
        if let Some(app) = self.app.get() {
            for (label, window) in app.webview_windows() {
                if label.starts_with("preview-") {
                    let _ = window.close();
                }
            }
        }
    }
    fn owns_foreground(&self) -> bool {
        #[cfg(windows)]
        {
            windows::owns_foreground()
        }
        #[cfg(not(windows))]
        {
            self.app.get().is_some_and(|app| {
                app.webview_windows()
                    .values()
                    .any(|w| w.is_focused().unwrap_or(false))
            })
        }
    }
    fn lock(&self) {
        clipboard::clear();
        self.mask();
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
    language: Option<String>,
) -> Result<Value, String> {
    let b = binding(&window)?;
    let host = state.host()?;
    let mut request: Request = serde_json::from_value(request).map_err(|_| "INVALID_REQUEST")?;
    let hello = matches!(&request, Request::UnlockHello {});
    let closing = matches!(&request, Request::Lock {} | Request::Logout {});
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _modal = hello.then(|| state.modal());
        let ru=language.as_deref()==Some("ru");
        let revoke=if let Request::Device{action,value:Some(value),confirmed:true}=&request {
            if action=="revoke" {Some(host.revoke_preview(generation,value).map_err(|e|e.0.to_owned())?)}else{None}
        }else{None};
        let pairing_preview=if matches!(&request,Request::Pairing{request:anynote_windows_native::pairing::Command::Approve{confirmed:true}|anynote_windows_native::pairing::Command::Confirm{confirmed:true}|anynote_windows_native::pairing::Command::Cancel{confirmed:true}}){Some(host.pairing_command(host.capability(generation).map_err(|e|e.0.to_owned())?.as_ref(),&anynote_windows_native::pairing::Command::Status{}).map_err(|e|e.0.to_owned())?)}else{None};
        let copy_preview=if let Request::CopyNote{source_group,destination_group,revision_id,..}=&request{Some(host.execute(&b,generation,Request::CopyPreview{source_group:source_group.clone(),destination_group:destination_group.clone(),revision_id:revision_id.clone()}).map_err(|e|e.0.to_owned())?)}else{None};
        let consent = match &request {
            Request::CopyNote {confirmed:true,..}=>Some(format!("{}\n{}",if ru{"Создать отдельный черновик с этими проверенными получателями? Исходная запись сохраняется."}else{"Create a separate draft for these verified recipients? The original is retained."},serde_json::to_string_pretty(&copy_preview.as_ref().unwrap()["preview"]).map_err(|_|"INVALID_REQUEST")?)),
            Request::RecoverDraft {draft_id,destination_group,destination_thread,confirmed:true}=>Some(format!("{}\nDraft: {}\nGroup: {}\nThread: {}",if ru{"Сохранить отдельную копию в вашей личной группе? Исходный черновик сохраняется."}else{"Save a separate copy in your private group? The original draft is retained."},draft_id,destination_group,destination_thread)),
            Request::ResolveDraft {draft_id,confirmed:true}=>Some(format!("{}\n{}",if ru{"Опубликовать проверенный результат объединения всех выбранных конфликтующих веток?"}else{"Publish the reviewed resolution of all selected conflict branches?"},draft_id)),
            Request::Shared {group_id,action,target_account_id,role,confirmed:true}=>Some(format!("{}\nGroup: {}\nAction: {}\nAccount: {}\nRole: {}",if ru{"Применить изменение доступа к общей группе?"}else{"Apply this shared-group access change?"},group_id,action,target_account_id.as_deref().unwrap_or("—"),role.as_deref().unwrap_or("—"))),
            Request::Device {confirmed:true,..}=>Some(if let Some(preview)=&revoke {format!("{}\n{}",if ru{"Отозвать эти устройства и все перечисленные дочерние устройства?"}else{"Revoke these devices and every listed descendant?"},serde_json::to_string(&preview["affected"]).map_err(|_|"INVALID_REQUEST")?)}else{if ru{"Подтвердить выбранное изменение доверенных устройств?"}else{"Confirm the selected trusted-device change?"}.into()}),
            Request::RevokeSession {session_id,confirmed:true}=>Some(format!("{}\n{}",if ru{"Завершить эту сессию?"}else{"Revoke this session?"},session_id)),
            Request::Retention {group_id,apply:true,confirmed:true}=>Some(format!("{}\n{}",if ru{"Применить проверенную политику хранения этой группы?"}else{"Apply the reviewed retention policy to this group?"},group_id)),
            Request::ObjectAction {object_id,action,confirmed:true,..}=>Some(format!("{}\n{}: {}",if ru{"Применить действие к этой записи?"}else{"Apply this action to this object?"},action,object_id)),
            Request::Pairing{..} if pairing_preview.is_some()=>Some(format!("{}\n{}",if ru{"Сравните аккаунт, отпечаток нового устройства и срок действия на обоих устройствах. Подтвердить выбранный шаг подключения?"}else{"Compare the account, new-device fingerprint and expiry on both devices. Confirm this pairing step?"},serde_json::to_string_pretty(&pairing_preview.as_ref().unwrap()["ceremony"]).map_err(|_|"INVALID_REQUEST")?)),
            _=>None,
        };
        if let Some(description) = consent {
            let _modal = state.modal();
            let approved = rfd::MessageDialog::new()
                .set_parent(&window)
                .set_title("AnyNote confirmation")
                .set_description(description)
                .set_buttons(rfd::MessageButtons::YesNo)
                .show()
                == rfd::MessageDialogResult::Yes;
            if !approved {
                return Err("CANCELLED".into());
            }
        }

        if let (Some(preview),Request::Device{value,..})=(revoke,&mut request){
            *value=Some(json!({"targets":preview["targets"],"head":preview["head"]}));
        }
        let result = host.execute(&b, generation, request);
        if closing || host.current() != generation {
            clipboard::clear();
            state.mask();
        }
        result.map_err(|e| e.0.into())
    })
    .await
    .map_err(|_| "HOST_UNAVAILABLE")?
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum ProfileCommand {
    List {},
    Open {
        profile_id: String,
    },
    Create {
        phrase: String,
        hello: bool,
    },
    Resume {
        profile_id: String,
        phrase: String,
        hello: bool,
    },
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
    tauri::async_runtime::spawn_blocking(move||->Result<Value,String>{
  match request {
   ProfileCommand::List{}=>{
    let mut rows=Vec::new();
    for entry in std::fs::read_dir(&state.root).map_err(|_|"STORAGE_UNAVAILABLE")?{
     let entry=entry.map_err(|_|"STORAGE_UNAVAILABLE")?;
     if !entry.file_type().map_err(|_|"STORAGE_UNAVAILABLE")?.is_dir(){continue;}
     let complete=entry.path().join("profile.json").exists();
     let path=entry.path().join(if complete{"profile.json"}else{"profile-pending.json"});
     if !path.exists(){continue;}
     let bytes=std::fs::read(path).map_err(|_|"STORAGE_UNAVAILABLE")?;
     let value=anynote_crypto_core::codec::strict(&bytes,65536).map_err(|_|"INVALID_PROFILE")?;
     rows.push(json!({"profile_id":entry.file_name().to_string_lossy(),"setup_pending":!complete,"account_id":value["scope"]["account_id"],"issuer":value["service"]["issuer"]}));
    }Ok(json!({"items":rows}))
   },
   ProfileCommand::Open{profile_id}=>{
    profile_id_check(&profile_id)?;state.lock();
    let mut host=Host::open(&state.root.join(profile_id)).map_err(|e|e.0)?;
    host.generation=state.generation.clone();state.generation.fetch_add(1,Ordering::SeqCst);
    *state.host.lock().map_err(|_|"HOST_BUSY")?=Some(Arc::new(host));Ok(json!({"state":"locked"}))
   },
   command @ (ProfileCommand::Create{..}|ProfileCommand::Resume{..})=>{
    let(resume,phrase,hello)=match command {
     ProfileCommand::Create{phrase,hello}=>(None,phrase,hello),
     ProfileCommand::Resume{profile_id,phrase,hello}=>(Some(profile_id),phrase,hello),
     _=>unreachable!()
    };
    let phrase=zeroize::Zeroizing::new(phrase);let _modal=state.modal();
    let selected=rfd::FileDialog::new().set_parent(&window).add_filter("Independently trusted public service configuration",&["json"]).pick_file().ok_or("CANCELLED")?;
    let mut source=Source::open(&selected,65536).map_err(|e|e.0)?;
    let bytes=source.small(65536).map_err(|e|e.0)?;
    let service:Service=serde_json::from_value(anynote_crypto_core::codec::strict(&bytes,65536).map_err(|e|e.0)?).map_err(|_|"INVALID_SERVICE_CONFIGURATION")?;
    let profile_id=if let Some(id)=&resume{id.clone()}else{anynote_crypto_core::crypto::b64(&anynote_crypto_core::crypto::random_key().map_err(|e|e.0)?[..16])};
    profile_id_check(&profile_id)?;
    let result=if resume.is_some(){Host::resume_setup(&state.root.join(&profile_id),service,&phrase,hello,b.hwnd)}else{Host::create(&state.root.join(&profile_id),service,&phrase,hello,b.hwnd)};
    let mut host=result.map_err(|e|e.0)?;state.lock();host.generation=state.generation.clone();state.generation.fetch_add(1,Ordering::SeqCst);
    *state.host.lock().map_err(|_|"HOST_BUSY")?=Some(Arc::new(host));Ok(json!({"profile_id":profile_id,"state":"locked"}))
   }
  }
 }).await.map_err(|_|"HOST_UNAVAILABLE")?
}
fn profile_id_check(id: &str) -> Result<(), String> {
    if id.len() == 22
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        Ok(())
    } else {
        Err("INVALID_PROFILE".into())
    }
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum FileCommand {
    PairingPng {},
    SavePairingPng {
        png_base64: String,
    },
    ExportAccountCard {},
    ExportGroupCard {
        group_id: String,
    },
    ImportGroupCard {
        accept: bool,
    },
    InviteAccount {
        group_id: String,
        role: String,
    },
    OwnershipProposal {
        group_id: String,
        account_id: String,
        device_id: String,
    },
    OwnershipConsent {
        group_id: String,
    },
    OwnershipCommit {
        group_id: String,
    },
    SaveOwnership {
        group_id: String,
    },
    CopySavedText {
        group_id: String,
        object_id: String,
        revision_id: String,
    },
    CopyFile {
        draft_id: String,
        destination_group: String,
    },
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
    RecoverExport {
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
fn pick_public(
    window: &tauri::WebviewWindow,
    state: &Arc<State>,
    ru: bool,
) -> Result<Value, String> {
    let selected = {
        let _modal = state.modal();
        rfd::FileDialog::new()
            .set_parent(window)
            .add_filter(
                if ru {
                    "Независимо проверенный публичный документ"
                } else {
                    "Independently trusted public document"
                },
                &["json"],
            )
            .pick_file()
            .ok_or("CANCELLED")?
    };
    let mut source = Source::open(&selected, 4194304).map_err(|e| e.0)?;
    anynote_crypto_core::codec::strict(&source.small(4194304).map_err(|e| e.0)?, 4194304)
        .map_err(|e| e.0.into())
}
fn save_public(
    window: &tauri::WebviewWindow,
    state: &Arc<State>,
    host: &Arc<Host>,
    generation: u64,
    ru: bool,
    name: &str,
    value: &Value,
) -> Result<Value, String> {
    let selected = {
        let _modal = state.modal();
        rfd::FileDialog::new()
            .set_parent(window)
            .set_file_name(name)
            .add_filter(
                if ru {
                    "Публичный документ"
                } else {
                    "Public document"
                },
                &["json"],
            )
            .save_file()
            .ok_or("CANCELLED")?
    };
    host.capability(generation).map_err(|e| e.0)?;
    let bytes = anynote_crypto_core::codec::canonical(value).map_err(|e| e.0)?;
    if bytes.len() > 4194304 {
        return Err("RESOURCE_LIMIT".into());
    }
    let mut output =
        anynote_windows_native::selection::Destination::create(&selected).map_err(|e| e.0)?;
    std::io::Write::write_all(&mut output, &bytes).map_err(|_| "STORAGE_UNAVAILABLE")?;
    host.capability(generation).map_err(|e| e.0)?;
    output.finish().map_err(|e| e.0)?;
    Ok(json!({"state":"SAVED","scope":"public-proof-only"}))
}
fn public_consent(
    window: &tauri::WebviewWindow,
    state: &Arc<State>,
    ru: bool,
    description: &str,
) -> Result<(), String> {
    let _modal = state.modal();
    if rfd::MessageDialog::new()
        .set_parent(window)
        .set_title(if ru {
            "AnyNote — независимая проверка"
        } else {
            "AnyNote independent verification"
        })
        .set_description(description)
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        != rfd::MessageDialogResult::Yes
    {
        return Err("CANCELLED".into());
    }
    Ok(())
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
    language: Option<String>,
) -> Result<Value, String> {
    binding(&window)?;
    let ru = language.as_deref() == Some("ru");
    let state = state.inner().clone();
    let host = state.host()?;
    let app = window.app_handle().clone();
    let request: FileCommand = serde_json::from_value(request).map_err(|_| "INVALID_REQUEST")?;
    tauri::async_runtime::spawn_blocking(move||{host.capability(generation).map_err(|e|e.0)?;match request{
  FileCommand::ExportAccountCard{}=>{let card=host.account_card(generation).map_err(|e|e.0)?;save_public(&window,&state,&host,generation,ru,"AnyNote-public-account.json",&card)},
  FileCommand::ExportGroupCard{group_id}=>{let card=host.group_card(generation,&group_id).map_err(|e|e.0)?;save_public(&window,&state,&host,generation,ru,"AnyNote-independent-group.json",&card)},
  FileCommand::ImportGroupCard{accept}=>{let card=pick_public(&window,&state,ru)?;public_consent(&window,&state,ru,&format!("{} {}\n{}",if ru{"Проверьте карточку группы и исходный отпечаток её владельца по независимому доверенному каналу."}else{"Verify this independently obtained group card and its genesis owner root through a trusted private channel."},if accept{if ru{"Принять ожидающее приглашение в группу?"}else{"Accept its pending membership invitation?"}}else{if ru{"Импортировать это независимое подтверждение доверия?"}else{"Import this independent trust anchor?"}},serde_json::to_string_pretty(&card["pin"]).map_err(|_|"INVALID_REQUEST")?))?;host.adopt_group_card(generation,card,accept).map_err(|e|e.0.into())},
  FileCommand::InviteAccount{group_id,role}=>{let card=pick_public(&window,&state,ru)?;public_consent(&window,&state,ru,&format!("{}\nGroup: {}\nRole: {}\n{}",if ru{"Пригласить этот независимо проверенный аккаунт с полной сохранённой историей?"}else{"Invite this independently verified account with full retained history?"},group_id,role,serde_json::to_string_pretty(&card["pins"]).map_err(|_|"INVALID_REQUEST")?))?;host.invite_account_card(generation,&group_id,&card,&role).map_err(|e|e.0.into())},
  FileCommand::OwnershipProposal{group_id,account_id,device_id}=>{public_consent(&window,&state,ru,&format!("{}\nGroup: {}\nAccount: {}\nDevice: {}",if ru{"Предложить передачу владения? Новый владелец должен независимо подтвердить согласие."}else{"Propose ownership transfer? The incoming owner must independently consent."},group_id,account_id,device_id))?;let policy=host.ownership_proposal(generation,&group_id,&account_id,&device_id).map_err(|e|e.0)?;save_public(&window,&state,&host,generation,ru,"AnyNote-ownership-proposal.json",&policy)},
  FileCommand::OwnershipConsent{group_id}=>{let cosign=true;let policy=pick_public(&window,&state,ru)?;public_consent(&window,&state,ru,&format!("{}\n{}",if cosign{if ru{"Согласиться стать владельцем группы? Проверьте личности прежнего и нового владельца."}else{"Consent to becoming this group's owner? Verify both current and incoming owner identities."}}else{if ru{"Завершить передачу владения с независимым согласием нового владельца?"}else{"Complete the independently consented ownership transfer?"}},serde_json::to_string_pretty(&policy["body"]).map_err(|_|"INVALID_REQUEST")?))?;let result=host.ownership_step(generation,&group_id,&policy,cosign).map_err(|e|e.0)?;if cosign{save_public(&window,&state,&host,generation,ru,"AnyNote-ownership-consented.json",&result["policy"])}else{Ok(result["result"].clone())}},
  FileCommand::OwnershipCommit{group_id}=>{let cosign=false;let policy=pick_public(&window,&state,ru)?;public_consent(&window,&state,ru,&format!("{}\n{}",if cosign{if ru{"Согласиться стать владельцем группы? Проверьте личности прежнего и нового владельца."}else{"Consent to becoming this group's owner? Verify both current and incoming owner identities."}}else{if ru{"Завершить передачу владения с независимым согласием нового владельца?"}else{"Complete the independently consented ownership transfer?"}},serde_json::to_string_pretty(&policy["body"]).map_err(|_|"INVALID_REQUEST")?))?;let result=host.ownership_step(generation,&group_id,&policy,cosign).map_err(|e|e.0)?;if cosign{save_public(&window,&state,&host,generation,ru,"AnyNote-ownership-consented.json",&result["policy"])}else{Ok(result["result"].clone())}},
  FileCommand::SaveOwnership{group_id}=>{let policy=host.saved_ownership_policy(generation,&group_id).map_err(|e|e.0)?;save_public(&window,&state,&host,generation,ru,"AnyNote-ownership-retained.json",&policy)},
  FileCommand::SavePairingPng{png_base64}=>{
    if png_base64.len()>5592408{return Err("RESOURCE_LIMIT".into());}
    let bytes=anynote_crypto_core::crypto::un64(&png_base64).map_err(|_|"PAIRING_PNG_REQUIRED")?;
    if bytes.len()<33 || bytes.len()>4194304 || &bytes[..8]!=b"\x89PNG\r\n\x1a\n" || &bytes[12..16]!=b"IHDR"{return Err("PAIRING_PNG_REQUIRED".into());}
    let width=u32::from_be_bytes(bytes[16..20].try_into().unwrap());let height=u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    if width==0||height==0||width>2048||height>2048{return Err("PAIRING_PNG_REQUIRED".into());}
    let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-private-pairing.png").add_filter("PNG",&["png"]).save_file().ok_or("CANCELLED")?};
    host.capability(generation).map_err(|e|e.0)?;
    let mut output=anynote_windows_native::selection::Destination::create(&selected).map_err(|e|e.0)?;
    std::io::Write::write_all(&mut output,&bytes).map_err(|_|"STORAGE_UNAVAILABLE")?;
    host.capability(generation).map_err(|e|e.0)?;output.finish().map_err(|e|e.0)?;
    Ok(json!({"state":"SAVED","scope":"one-time-private-pairing-QR"}))
  },
  FileCommand::PairingPng{}=>{let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).add_filter("Pairing PNG",&["png"]).pick_file().ok_or("CANCELLED")?};let mut source=Source::open(&selected,4194304).map_err(|e|e.0)?;let bytes=source.small(4194304).map_err(|e|e.0)?;if bytes.len()<33 || &bytes[..8]!=b"\x89PNG\r\n\x1a\n" || &bytes[12..16]!=b"IHDR" {return Err("PAIRING_PNG_REQUIRED".into());}let width=u32::from_be_bytes(bytes[16..20].try_into().unwrap());let height=u32::from_be_bytes(bytes[20..24].try_into().unwrap());if width==0||height==0||width>2048||height>2048{return Err("PAIRING_PNG_REQUIRED".into());}host.capability(generation).map_err(|e|e.0)?;Ok(json!({"png_base64":anynote_crypto_core::crypto::b64(&bytes)}))},
  FileCommand::CopySavedText{group_id,object_id,revision_id}=>{
    let opened=host.execute(&binding(&window)?,generation,Request::Open{group_id,object_id,revision_id}).map_err(|e|e.0)?;
    public_consent(&window,&state,ru,if ru{"Передать сохранённый текст в системный буфер обмена? Другие приложения смогут его прочитать. Через 30 секунд и при блокировке AnyNote попытается очистить только свою неизменённую копию."}else{"Copy the saved text to the system clipboard? Other applications can read it. After 30 seconds and on lock, AnyNote attempts to clear only its own unchanged copy."})?;
    host.capability(generation).map_err(|e|e.0)?;
    let text=zeroize::Zeroizing::new(format!("{}\n\n{}",opened["payload"]["title"].as_str().unwrap_or(""),opened["payload"]["markdown"].as_str().unwrap_or("")));
    clipboard::copy(binding(&window)?.hwnd,&text)?;Ok(json!({"state":"COPIED","best_effort_clear_seconds":30}))
  },
  FileCommand::CopyFile{draft_id,destination_group}=>{
    let preview=host.selected_file_copy_preview(generation,&draft_id,&destination_group).map_err(|e|e.0)?;
    public_consent(&window,&state,ru,&format!("{}\n{}",if ru{"Скопировать только выбранный исходный файл с новыми ключами для этих получателей? Исходные данные сохраняются."}else{"Copy only the selected original file with fresh keys for these recipients? Original data is retained."},serde_json::to_string_pretty(&preview["preview"]).map_err(|_|"INVALID_REQUEST")?))?;
    let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).pick_file().ok_or("CANCELLED")?};
    let source=Source::open(&selected,1000000000).map_err(|e|e.0)?;
    let job=host.start_selected_file_copy(generation,&draft_id,&destination_group,source,preview["digest"].as_str().ok_or("INVALID_REQUEST")?).map_err(|e|e.0)?;
    Ok(json!({"job_id":job,"source_retained":true}))
  },
  FileCommand::Upload{group_id,resume}=>{let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).pick_file().ok_or("CANCELLED")?};let source=Source::open(&selected,1000000000).map_err(|e|e.0)?;let job=host.start_upload(generation,group_id,source,resume).map_err(|e|e.0)?;Ok(json!({"job_id":job}))},
  FileCommand::Download{group_id,file_version_id,offline}=>{let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-file.bin").save_file().ok_or("CANCELLED")?};let job=host.start_download(generation,group_id,file_version_id,&selected,offline).map_err(|e|e.0)?;Ok(json!({"job_id":job}))},
  FileCommand::Export{group_ids,history,trash,kib_per_second}=>{let plan=host.prepare_export(generation,&group_ids,history,trash,kib_per_second).map_err(|e|e.0)?;let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-export.age").save_file().ok_or("CANCELLED")?};let(node,script,manifest)=assets(&app)?;let job=host.jobs.start(generation).map_err(|e|e.0)?;let id=job.id.clone();std::thread::spawn(move||{let a=Assets{node:&node,script:&script,node_sha:manifest["node_sha256"].as_str().unwrap_or(""),script_sha:manifest["script_sha256"].as_str().unwrap_or("")};let r=host.export_archive(generation,plan,&selected,&a,job.clone());job.finish(r);});Ok(json!({"job_id":id}))},
  FileCommand::RecoverExport{export_id}=>{let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-recovered-export.age").save_file().ok_or("CANCELLED")?};host.recover_export(generation,&export_id,&selected).map_err(|e|e.0.into())},
  FileCommand::SaveKit{export_id}=>{let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).set_file_name("AnyNote-recovery-kit.json").save_file().ok_or("CANCELLED")?};host.save_kit(generation,&export_id,&selected).map_err(|e|e.0.into())},
  FileCommand::InspectImport{destination,resume}=>{let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).add_filter("Encrypted archive",&["age"]).pick_file().ok_or("CANCELLED")?};let source=Source::open(&selected,116010000000).map_err(|e|e.0)?;let selected={let _modal=state.modal();rfd::FileDialog::new().set_parent(&window).add_filter("Separate recovery kit",&["json"]).pick_file().ok_or("CANCELLED")?};let mut selected=Source::open(&selected,65536).map_err(|e|e.0)?;let mut kit=anynote_crypto_core::codec::strict(&selected.small(65536).map_err(|e|e.0)?,65536).map_err(|e|e.0)?;let(node,script,manifest)=assets(&app)?;let a=Assets{node:&node,script:&script,node_sha:manifest["node_sha256"].as_str().unwrap_or(""),script_sha:manifest["script_sha256"].as_str().unwrap_or("")};let result=host.inspect_import(generation,source,kit.take(),destination.as_deref(),resume.as_deref(),&a);result.map_err(|e|e.0.into())},
  FileCommand::ConfirmImport{import_id,audience_digest}=>Ok(json!({"job_id":host.start_import(generation,&import_id,&audience_digest).map_err(|e|e.0)?})),
  FileCommand::Preview{group_id,file_version_id}=>{
   let bytes=zeroize::Zeroizing::new(host.read_preview(generation,&group_id,&file_version_id).map_err(|e|e.0)?);host.capability(generation).map_err(|e|e.0)?;
   let payload=serde_json::to_string(&json!({"bytes":anynote_crypto_core::crypto::b64(&bytes)})).map_err(|_|"PREVIEW_UNAVAILABLE")?;
   let data=Arc::new(Mutex::new(Some(payload)));let label=format!("preview-{}",anynote_crypto_core::crypto::b64(&anynote_crypto_core::crypto::random_key().map_err(|e|e.0)?[..16]));
   let preview_host=host.clone();let window_state=state.clone();
   let preview_builder=tauri::WebviewWindowBuilder::new(&app,&label,tauri::WebviewUrl::App("auth/preview.html".into())).title("AnyNote file preview").parent(&window).map_err(|_|"PREVIEW_UNAVAILABLE")?.devtools(false).incognito(true)
    .on_navigation(|url|["http://tauri.localhost","tauri://localhost"].contains(&url.origin().ascii_serialization().as_str())&&url.username().is_empty()&&url.password().is_none()&&url.path()=="/auth/preview.html"&&url.query().is_none()&&url.fragment().is_none())
    .on_new_window(|_,_|tauri::webview::NewWindowResponse::Deny)
    .on_download(|_,_|false)
    .on_page_load(move|view,page|{if page.event()==tauri::webview::PageLoadEvent::Finished{if preview_host.current()!=generation{let _=view.close();return;}if let Ok(mut data)=data.lock()&&let Some(payload)=data.take(){let _=view.eval(format!("window.dispatchEvent(new CustomEvent('anynote-preview',{{detail:{payload}}}))"));}}})
    ;
   #[cfg(feature = "integration-harness")]
   let preview_builder=preview_builder.data_directory(harness_browser_directory()).additional_browser_args(harness_browser_arguments());
   let preview=preview_builder.build().map_err(|_|"PREVIEW_UNAVAILABLE")?;
   preview.on_window_event(move|event|{if matches!(event,tauri::WindowEvent::Focused(false))&&!window_state.owns_foreground(){window_state.lock();if let Some(app)=window_state.app.get(){let _=app.emit("vault-locked",json!({"reason":"background"}));}}});
   Ok(json!({"state":"OPENED","isolation":"separate window, no native IPC permissions, bounded P13 workers"}))
  }
 }}).await.map_err(|_|"HOST_UNAVAILABLE")?
}
// WebView2 environments with different browser arguments must not share a data
// directory (the maintained builder documents this contract). CI-only CDP uses
// an isolated per-process browser profile; all preview windows share that scope.
// Native encrypted profiles keep their normal app-local path across restarts.
#[cfg(feature = "integration-harness")]
fn harness_browser_directory() -> PathBuf {
    std::env::temp_dir().join(format!("anynote-p14-webview-{}", std::process::id()))
}
#[cfg(feature = "integration-harness")]
fn harness_browser_arguments() -> &'static str {
    // Use the maintained native options: the hosted runtime did not forward the
    // environment-based arguments. Keep Wry defaults and loopback-only CI CDP.
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --autoplay-policy=no-user-gesture-required --remote-debugging-port=9223 --remote-debugging-address=127.0.0.1"
}
fn main() {
    // WebView2 honors debugging environment overrides independently of its UI setting.
    // Only the explicitly built CI harness may enable local CDP; the owner installer
    // removes those overrides before any WebView or worker thread exists.
    #[cfg(not(feature = "integration-harness"))]
    for name in [
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
    ] {
        unsafe {
            std::env::remove_var(name);
        }
    }
    tauri::Builder::default()
        .plugin(
            tauri::plugin::Builder::<tauri::Wry, ()>::new("navigation-boundary")
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
                updating: std::sync::atomic::AtomicBool::new(false),
                generation: Arc::new(AtomicU64::new(0)),
                app: OnceLock::new(),
            });
            let _ = state.app.set(app.handle().clone());
            app.manage(state.clone());
            let window_builder =
                tauri::WebviewWindowBuilder::from_config(app, &app.config().app.windows[0])?
                    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                    .on_download(|_, _| false);
            #[cfg(feature = "integration-harness")]
            let window_builder = window_builder
                .data_directory(harness_browser_directory())
                .additional_browser_args(harness_browser_arguments());
            let window = window_builder.build()?;
            #[cfg(windows)]
            windows::attach(&window, state.clone())?;
            let handle = app.handle().clone();
            window.on_window_event(move |event| match event {
                tauri::WindowEvent::Focused(false)
                    if state.modal.load(Ordering::SeqCst) == 0 && !state.owns_foreground() =>
                {
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

struct UpdatePermit(Arc<State>);
impl Drop for UpdatePermit {
    fn drop(&mut self) {
        self.0.updating.store(false, Ordering::SeqCst);
    }
}
struct UpdateWatch(Arc<std::sync::atomic::AtomicBool>);
impl Drop for UpdateWatch {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
fn watch_update(
    host: Arc<Host>,
    generation: u64,
    abort: futures_util::future::AbortHandle,
) -> UpdateWatch {
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = done.clone();
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            if host.current() != generation {
                abort.abort();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
    UpdateWatch(done)
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
    if state
        .updating
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("HOST_BUSY".into());
    }
    let _permit = UpdatePermit(state.inner().clone());
    let host = state.host()?;
    host.capability(generation).map_err(|e| e.0)?;
    let policy_path = state
        .root
        .parent()
        .ok_or("STORAGE_UNAVAILABLE")?
        .join("update-policy.json");
    let mut selected_policy =
        Source::open(&policy_path, 65536).map_err(|_| "UPDATE_TRUST_NOT_CONFIGURED")?;
    let bytes = selected_policy
        .small(65536)
        .map_err(|_| "INVALID_UPDATE_POLICY")?;
    let policy: anynote_windows_native::updates::UpdatePolicy =
        serde_json::from_value(anynote_crypto_core::codec::strict(&bytes, 65536).map_err(|e| e.0)?)
            .map_err(|_| "INVALID_UPDATE_POLICY")?;
    policy.validate().map_err(|e| e.0)?;
    use tauri_plugin_updater::UpdaterExt;
    let updater = window
        .app_handle()
        .updater_builder()
        .timeout(std::time::Duration::from_secs(30))
        .configure_client(|client| {
            client
                .https_only(true)
                .connect_timeout(std::time::Duration::from_secs(10))
        })
        .pubkey(policy.public_key.clone())
        .endpoints(vec![
            tauri::Url::parse(&policy.endpoint).map_err(|_| "INVALID_UPDATE_POLICY")?,
        ])
        .map_err(|_| "INVALID_UPDATE_POLICY")?
        .build()
        .map_err(|_| "INVALID_UPDATE_POLICY")?;
    let (check_abort, check_registration) = futures_util::future::AbortHandle::new_pair();
    let check_watch = watch_update(host.clone(), generation, check_abort);
    let checked = futures_util::future::Abortable::new(updater.check(), check_registration)
        .await
        .map_err(|_| "UPDATE_CANCELLED")?
        .map_err(|_| "UPDATE_UNAVAILABLE")?;
    drop(check_watch);
    host.capability(generation).map_err(|e| e.0)?;
    let Some(mut next) = checked else {
        return Ok(json!({"state":"CURRENT"}));
    };
    next.timeout = Some(std::time::Duration::from_secs(1800));
    let claims = policy
        .signed_claims(
            &window.app_handle().package_info().version.to_string(),
            &next.version,
            next.download_url.as_str(),
            &next.raw_json["anynote_claims"],
            next.raw_json["anynote_claims_signature"]
                .as_str()
                .ok_or("UPDATE_INTEGRITY_FAILURE")?,
        )
        .map_err(|e| e.0)?;
    if !install {
        return Ok(
            json!({"state":"AVAILABLE","version":next.version,"channel":policy.channel,"signature_required":true}),
        );
    }
    if !confirmed {
        return Err("CONFIRMATION_REQUIRED".into());
    }
    let dialog_window = window.clone();
    let dialog_state = state.inner().clone();
    let description = format!(
        "Install AnyNote {} from the operator-configured {} channel? Local encrypted drafts and recovery journals are retained.",
        claims.version, claims.channel
    );
    let approved = tauri::async_runtime::spawn_blocking(move || {
        let _modal = dialog_state.modal();
        rfd::MessageDialog::new()
            .set_parent(&dialog_window)
            .set_title("AnyNote update")
            .set_description(description)
            .set_buttons(rfd::MessageButtons::YesNo)
            .show()
            == rfd::MessageDialogResult::Yes
    })
    .await
    .map_err(|_| "HOST_UNAVAILABLE")?;
    if !approved {
        return Err("CANCELLED".into());
    }
    host.capability(generation).map_err(|e| e.0)?;
    let (abort, registration) = futures_util::future::AbortHandle::new_pair();
    let download_watch = watch_update(host.clone(), generation, abort.clone());
    let cancel = abort.clone();
    let owned = host.clone();
    let mut downloaded = 0u64;
    let result = futures_util::future::Abortable::new(
        next.download(
            move |bytes, total| {
                downloaded = downloaded.saturating_add(bytes as u64);
                if downloaded > 536870912
                    || total.is_some_and(|n| n > 536870912)
                    || owned.current() != generation
                {
                    cancel.abort();
                }
            },
            || {},
        ),
        registration,
    )
    .await;
    drop(download_watch);
    let bytes = result
        .map_err(|_| "UPDATE_CANCELLED_OR_TOO_LARGE")?
        .map_err(|_| "UPDATE_INTEGRITY_FAILURE")?;
    if anynote_crypto_core::crypto::hash(&bytes) != claims.artifact_sha256 {
        return Err("UPDATE_INTEGRITY_FAILURE".into());
    }
    host.capability(generation).map_err(|e| e.0)?;
    state.lock();
    next.install(bytes).map_err(|_| "UPDATE_INSTALL_FAILED")?;
    Ok(json!({"state":"INSTALLING"}))
}
