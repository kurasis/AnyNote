const button=document.querySelector('#start'),output=document.querySelector('#status'),input=document.querySelector('#saved-file');
const worker=new Worker(new URL('./device-worker.js',import.meta.url),{type:'module'});
let pending,stage='run',report,prepared,sharing=false,releaseSession;
const BUILD=__DEVICE_BUILD__;
function show(text){output.textContent=text;}
function call(data){
  if(pending)return Promise.reject(new Error('Test already busy'));
  return new Promise((resolve,reject)=>{
    const timeout=()=>{pending.timer=setTimeout(()=>{
      pending=null;worker.postMessage({kind:'lock'});reject(new Error('Worker did not respond; reload to clean marked test files'));
    },120000);};
    pending={resolve,reject,timeout};timeout();worker.postMessage(data);
  });
}
function attachEnvironment(value){return {...value,build:BUILD,user_agent:navigator.userAgent,
  installed_pwa:matchMedia('(display-mode: standalone)').matches,origin:location.origin,
  owner_reported_target:'iPhone 17 Pro / iOS 26.7.1; not verified by this page'};}
function finish(text){stage='report';button.disabled=false;button.textContent='Save report';show(text);releaseSession?.();releaseSession=null;}
worker.onmessage=({data})=>{
  if(data.kind==='progress'){
    if(pending){clearTimeout(pending.timer);pending.timeout();}
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
  button.disabled=true;show('Starting automatic checks…');
  report=attachEnvironment({status:'NOT RUN',physical_acceptance:false});
  if(!isSecureContext||!navigator.locks){finish('BLOCKED: trusted HTTPS and Web Locks are required. Save the report.');report.status='BLOCKED';return;}
  await navigator.locks.request('anynote-p01-device-kit',{ifAvailable:true},async(lock)=>{
    if(!lock){report.status='BLOCKED';finish('Another device test is running in a tab. Close it and reload this page.');return;}
    const held=new Promise(resolve=>{releaseSession=resolve;});
    try{
      const result=await call({kind:'run'});report=attachEnvironment(result.report);prepared=result;
      if(!navigator.share||!navigator.canShare?.({files:[result.file]})){
        report.files_destination='BLOCKED: Web Share of the verified disk File unavailable';
        await call({kind:'cleanup'});prepared=null;
        finish('Automatic local checks passed. This browser cannot share the verified 1 GB disk file. Save the report.');
      }else{
        stage='share';button.disabled=false;button.textContent='Save 1 GB to Files';
        show('Automatic local checks passed.\nTap the same button, choose “Save to Files”, and save the sample.\nThen select that saved file when asked so its size and SHA-256 can be checked.');
      }
    }catch(error){
      if(report.status==='NOT RUN')report={...report,status:'FAIL',error:String(error.message)};
      finish(`${report.status}: ${error.message}\nSave the report and send it back.`);
    }
    await held;
  });
}
button.addEventListener('click',async()=>{
  if(stage==='run'){await run();return;}
  if(stage==='share'){
    sharing=true;button.disabled=true;
    try{
      // Invoke directly in the click, before any await; user activation cannot be manufactured.
      await navigator.share({files:[prepared.file],title:'AnyNote P01 synthetic 1 GB export'});
      report.share='COMPLETED; this alone does not verify Files';
      stage='verify';button.disabled=false;button.textContent='Verify saved Files output';
      show('Choose the exact sample you just saved in Files. The page reads it in 8 MiB parts and compares size and SHA-256.');
    }catch(error){report.share=`BLOCKED_OR_CANCELLED: ${error.name}`;finish('Sharing did not complete. Save the report.');}
    finally{
      sharing=false;
      try{await call({kind:'cleanup'});report.temporary_export_cleanup='PASS';}
      catch{report.temporary_export_cleanup='FAIL: reload to clean marked files';}
      prepared=null;
      if(stage==='verify'){releaseSession?.();releaseSession=null;}
    }
  }else if(stage==='verify')input.click();
  else if(stage==='report'){
    const bytes=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});
    const url=URL.createObjectURL(bytes),link=document.createElement('a');
    link.href=url;link.download='anynote-p01-device-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),60000);
  }
});
input.addEventListener('change',async()=>{
  const file=input.files[0];if(!file)return;
  button.disabled=true;
  try{
    const {result}=await call({kind:'verify-file',file});
    const expected=report.files.find(item=>item.bytes===1000000000);
    if(!expected||result.sha256!==expected.sha256)throw new Error('Saved Files output digest mismatch');
    report.files_destination={status:'PASS_SELECTED_OUTPUT_HASH',...result,
      limitation:'Owner selected a file after sharing; destination provenance and device memory need physical review'};
    finish('Saved output: exact 1 GB size and SHA-256 match.\nTap “Save report” and send the JSON back. Physical acceptance remains open.');
  }catch(error){report.files_destination={status:'FAIL',error:error.message};finish(`Files verification failed: ${error.message}\nSave the report.`);}
  finally{input.value='';}
});
function hide(){
  if(sharing)return;worker.postMessage({kind:'lock'});
  if(prepared){prepared=null;report.files_destination='BLOCKED: lifecycle interruption before explicit share';
    call({kind:'cleanup'}).catch(()=>{}).finally(()=>finish('The test locked when this page left the foreground. Save the report; reload for a fresh trial.'));
  }
}
document.addEventListener('visibilitychange',()=>{if(document.hidden)hide();});
addEventListener('pagehide',hide);
if('serviceWorker'in navigator)navigator.serviceWorker.register('./service-worker.js',{scope:'./'}).catch(()=>{
  document.querySelector('#install').textContent='PWA installation cache is unavailable. Browser checks can run; installation is not verified.';
});
// Actual browser automation uses the same page/button/worker and selected-file path.
globalThis.deviceP01={get report(){return report;},get stage(){return stage;}};
