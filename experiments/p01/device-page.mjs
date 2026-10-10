import {checkpointKey,saveCheckpoint,readCheckpoint,savedOutputExpected} from './device-checkpoint.mjs';
const button=document.querySelector('#start'),output=document.querySelector('#status'),input=document.querySelector('#saved-file');
const saveButton=document.querySelector('#save-report'),newButton=document.querySelector('#new-trial'),reportText=document.querySelector('#report-text');
const worker=new Worker(new URL('./device-worker.js',import.meta.url),{type:'module'});
let pending,stage='run',report,prepared,sharing=false,releaseSession,lastPhase,writable=true;
const BUILD=__DEVICE_BUILD__,KEY=checkpointKey(location.pathname);
// Upgrade recovery reads only the documented sibling kit's diagnostic key, never other site data.
const PREVIOUS_KEY=checkpointKey(new URL('../anynote-p01-v011/',location.href).pathname);
function show(text){output.textContent=text;}
function renderReport(){saveButton.hidden=!report;reportText.value=report?JSON.stringify(report,null,2):'';}
function checkpoint(next=sharing?'handoff':stage){
  if(!writable)return false;
  try{saveCheckpoint(localStorage,KEY,next,report);renderReport();return true;}
  catch{report.diagnostic_persistence='BLOCKED: local diagnostic storage unavailable; save or copy this report before leaving';renderReport();return false;}
}
function call(data){
  if(pending)return Promise.reject(new Error('Test already busy'));
  return new Promise((resolve,reject)=>{
    const timeout=()=>{pending.timer=setTimeout(()=>{
      pending=null;worker.postMessage({kind:'lock'});reject(new Error('Worker did not respond; reopen to recover the report and clean marked test files'));
    },120000);};
    pending={resolve,reject,timeout};timeout();worker.postMessage(data);
  });
}
function attachEnvironment(value){return {...value,build:BUILD,user_agent:navigator.userAgent,
  installed_pwa:matchMedia('(display-mode: standalone)').matches,origin:location.origin,
  owner_reported_target:'iPhone 17 Pro / iOS 26.7.1; not verified by this page'};}
function finish(text){stage='report';checkpoint();button.disabled=false;button.textContent='Save report';newButton.hidden=false;show(text);releaseSession?.();releaseSession=null;}
function offerVerification(text){stage='verify';checkpoint();button.disabled=false;button.textContent='Verify saved Files output';newButton.hidden=false;show(text);}
function downloadReport(){
  checkpoint();renderReport();
  const bytes=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(bytes),link=document.createElement('a');
  link.href=url;link.download='anynote-p01-device-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),60000);
}
worker.onmessage=({data})=>{
  if(data.kind==='progress'){
    if(pending){clearTimeout(pending.timer);pending.timeout();}
    if(report&&lastPhase!==data.phase){lastPhase=data.phase;report.last_phase=data.phase;checkpoint();}
    const percent=data.count?` ${Math.round(data.index/data.count*100)}%`:'';
    show(`Running: ${data.phase}${percent}\nKeep this page in the foreground. The full trial uses an exact 1 GB file.`);return;
  }
  if(data.kind==='locked')return;
  if(!pending)return;
  clearTimeout(pending.timer);const task=pending;pending=null;
  if(data.kind==='error'){
    if(data.report)report=attachEnvironment(data.report);
    task.reject(new Error(data.message));
  }else task.resolve(data);
};
worker.onerror=()=>{if(pending){clearTimeout(pending.timer);pending.reject(new Error('Worker unavailable; check HTTPS and hosting policy'));pending=null;}};
async function run(){
  button.disabled=true;newButton.hidden=true;show('Starting automatic checks…');
  if(!isSecureContext||!navigator.locks){report=attachEnvironment({status:'BLOCKED',physical_acceptance:false});finish('BLOCKED: trusted HTTPS and Web Locks are required. Save the report.');return;}
  await navigator.locks.request('anynote-p01-device-kit',{ifAvailable:true},async(lock)=>{
    if(!lock){button.disabled=false;show('Another device test is running in a tab. Close it and reopen this page.');return;}
    writable=true;stage='run';report=attachEnvironment({status:'IN PROGRESS',physical_acceptance:false,started_at:new Date().toISOString()});
    if(!checkpoint()){report.status='BLOCKED';finish('Diagnostic storage unavailable. Save or copy the report below; enable site storage before starting a trial.');return;}
    const held=new Promise(resolve=>{releaseSession=resolve;});
    try{
      const result=await call({kind:'run'});report=attachEnvironment(result.report);prepared=result;
      report.synthetic_export_name=result.file.name;
      if(!navigator.share||!navigator.canShare?.({files:[result.file]})){
        report.files_destination='BLOCKED: Web Share of the verified disk File unavailable';
        await call({kind:'cleanup'});prepared=null;
        finish('Automatic local checks passed. This browser cannot share the verified 1 GB disk file. Save the report.');
      }else{
        stage='share';
        if(!checkpoint())throw new Error('Cannot safely open Files without a saved diagnostic checkpoint');
        button.disabled=false;button.textContent='Save 1 GB to Files';
        show(`Automatic local checks passed. Report saved on this device.\nTap the same button, choose “Save to Files”, and save ${report.synthetic_export_name} (1 GB).\nNext choose that .bin sample, not the JSON report.\nIf the app restarts, reopen it to verify the saved sample or save the report.`);
      }
    }catch(error){
      if(prepared){try{await call({kind:'cleanup'});report.temporary_export_cleanup='PASS';}
        catch{report.temporary_export_cleanup='FAIL: reopen to clean marked files';}prepared=null;}
      if(report.status==='IN PROGRESS')report={...report,status:'FAIL',error:String(error.message)};
      finish(`${report.status}: ${error.message}\nSave the report and send it back.`);
    }
    await held;
  });
}
button.addEventListener('click',async()=>{
  if(stage==='run'){await run();return;}
  if(stage==='share'){
    // Synchronous durable write and readback before the OS handoff preserves real activation.
    report.share='OUTCOME_UNKNOWN: system handoff requested; verify selected saved bytes';
    if(!checkpoint('handoff')){show('Cannot save recovery state. Save or copy the report before leaving.');return;}
    sharing=true;button.disabled=true;
    let shared=false,shareError;
    try{
      await navigator.share({files:[prepared.file],title:'AnyNote P01 synthetic 1 GB export'});
      report.share='COMPLETED; this alone does not verify Files';shared=true;
    }catch(error){report.share=`BLOCKED_OR_CANCELLED: ${error.name}`;shareError='Sharing did not complete. Save the report.';}
    finally{
      // Persist the outcome before cleanup; termination here still retains the report.
      checkpoint(shared?'verify':'report');
      try{await call({kind:'cleanup'});report.temporary_export_cleanup='PASS';}
      catch{report.temporary_export_cleanup='FAIL: reopen to clean marked files';}
      prepared=null;sharing=false;
      if(shared){offerVerification('Choose the saved synthetic-export-….bin sample (1 GB), NOT the JSON report. The page compares its exact size and SHA-256. You can choose again if you select the wrong file.');releaseSession?.();releaseSession=null;}
      else finish(shareError);
    }
  }else if(stage==='verify'){
    if(!checkpoint())return;input.click();
  }else if(stage==='report')downloadReport();
});
saveButton.addEventListener('click',downloadReport);
newButton.addEventListener('click',()=>{if(!pending&&!sharing)run();});
input.addEventListener('change',async()=>{
  const file=input.files[0];if(!file)return;
  button.disabled=true;stage='verifying';
  report.files_destination={status:'IN PROGRESS',selected_bytes:file.size,expected_bytes:1000000000};checkpoint();
  try{
    const expected=savedOutputExpected(report);
    if(!expected)throw new Error('No verified synthetic output digest in the retained report');
    const {result}=await call({kind:'verify-file',file});
    if(result.sha256!==expected.sha256)throw new Error('Saved Files output digest mismatch');
    report.files_destination={status:'PASS_SELECTED_OUTPUT_HASH',...result,selected_bytes:file.size,expected_bytes:1000000000,
      limitation:'Owner selected a file after sharing; destination provenance and device memory need physical review'};
    finish('Saved output: exact 1 GB size and SHA-256 match.\nTap “Save report” and send the JSON back. Physical acceptance remains open.');
  }catch(error){report.files_destination={status:'FAIL',error:error.message,selected_bytes:file.size,expected_bytes:1000000000};
    offerVerification(`Selected file: ${file.size.toLocaleString('en-US')} bytes. Expected: 1,000,000,000 bytes.\nVerification failed: ${error.message}\nChoose the saved synthetic-export-….bin sample, not anynote-p01-device-report.json. Tap again to select the right file; no automatic rerun is needed. You can save the current report below.`);}
  finally{input.value='';}
});
function hide(){
  if(sharing)return;worker.postMessage({kind:'lock'});
  if(prepared){prepared=null;report.files_destination='BLOCKED: lifecycle interruption before explicit share';
    // pagehide cannot wait for worker cleanup. Save diagnostics synchronously first.
    stage='report';checkpoint();
    call({kind:'cleanup'}).catch(()=>{}).finally(()=>finish('The test locked when this page left the foreground. Save the report; start a new trial when ready.'));
  }
}
document.addEventListener('visibilitychange',()=>{if(document.hidden)hide();});
addEventListener('pagehide',hide);
async function recover(){
  button.disabled=true;
  let stored,previousPath=false;
  try{stored=readCheckpoint(localStorage,KEY);
    if(!stored&&PREVIOUS_KEY!==KEY){stored=readCheckpoint(localStorage,PREVIOUS_KEY);previousPath=!!stored;}}
  catch{show('Saved diagnostics cannot be read. No automatic test was restarted. Start a new trial when ready.');button.disabled=false;return;}
  if(!stored){button.disabled=false;return;}
  report=stored.report;renderReport();
  report.recovery={status:'RESTORED_DIAGNOSTICS_ONLY',previous_stage:stored.stage,
    loaded_build:BUILD,restored_at:new Date().toISOString(),keys_restored:false,
    previous_kit_path:previousPath?'Documented sibling anynote-p01-v011/':null};
  if(!navigator.locks){finish('Retained report restored. Automatic cleanup unavailable; save the report.');return;}
  await navigator.locks.request('anynote-p01-device-kit',{ifAvailable:true},async(lock)=>{
    if(!lock){writable=false;stage='report';button.disabled=false;button.textContent='Save report';show('Retained report shown. Another tab owns the active trial; close it and reopen to recover safely.');return;}
    try{await call({kind:'cleanup-orphans'});report.temporary_export_cleanup='PASS';}
    catch{report.temporary_export_cleanup='FAIL: marked cleanup unavailable';}
    if((['handoff','verify','verifying'].includes(stored.stage)
      ||stored.stage==='report'&&report.files_destination?.status==='FAIL')&&savedOutputExpected(report)){
      if(stored.stage==='handoff')report.share='OUTCOME_UNKNOWN_AFTER_RESTART: verify the saved file; no share success inferred';
      offerVerification('Previous report restored.\nSelect the saved synthetic-export-….bin sample (1 GB), not the JSON report. You can select again after a mistake, or save the current report below. No automatic 1 GB rerun is needed.');
    }else{
      if(stored.stage==='run'){report.status='INTERRUPTED';report.error='Page restarted during automatic checks; no active keys or operation resumed';}
      if(stored.stage==='share')report.files_destination='NOT RUN: page restarted before a recorded OS handoff';
      finish('Previous report restored. Save it below. Start a new trial only when you want to repeat the automatic checks.');
    }
  });
}
if('serviceWorker'in navigator)navigator.serviceWorker.register('./service-worker.js',{scope:'./'}).catch(()=>{
  document.querySelector('#install').textContent='PWA installation cache is unavailable. Browser checks can run; installation is not verified.';
});
globalThis.deviceP01={get report(){return report;},get stage(){return stage;}};
await recover();
