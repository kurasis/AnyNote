// Synthetic feasibility UI only; never a usable vault or public service.
import { prepareExport, shareExport, discardExport, removeOrphans } from './export-staging.mjs';
const worker=new Worker('/physical-worker.js',{type:'module'});
let pending, locked=false;
let prepared,sharing=false;
const output=document.querySelector('output'), source=document.querySelector('input[type=file]');
function show(value){output.textContent=typeof value==='string'?value:JSON.stringify(value,null,2);}
function call(data){return new Promise((resolve,reject)=>{
  if(pending){reject(new Error('Experiment already running'));return;}
  const timer=setTimeout(()=>{worker.terminate();locked=true;pending=null;reject(new Error('No progress for 60 seconds; reload and restart'));},60000);
  pending={resolve,reject,timer};worker.postMessage(data);
});}
worker.onmessage=({data})=>{
  if(data.kind==='locked'){locked=true;return;}
  if(data.kind==='progress'){
    show(data);
    if(pending){clearTimeout(pending.timer);pending.timer=setTimeout(()=>{worker.terminate();pending.reject(new Error('No progress; restart required'));pending=null;},60000);}
    return;
  }
  if(!pending)return;clearTimeout(pending.timer);const active=pending;pending=null;
  if(data.kind==='error')active.reject(new Error(data.message));else active.resolve(data.result);
};
worker.onerror=(event)=>{if(pending){clearTimeout(pending.timer);pending.reject(new Error(event.message));pending=null;}show('Worker failed; reload to restart.');};
document.addEventListener('visibilitychange',()=>{
  if(document.hidden){locked=true;worker.postMessage({kind:'lock'});
    if(prepared&&!sharing){discardExport(prepared.id).catch(()=>{});prepared=null;}
    show('PAUSED_LOCKED: foreground/reselect alone cannot resume; restart with fresh keys and server session.');}
});
window.addEventListener('pagehide',()=>{locked=true;worker.postMessage({kind:'lock'});});
document.querySelector('#capabilities').onclick=async()=>{
  try{show({...await call({kind:'capabilities'}),installed:matchMedia('(display-mode: standalone)').matches,
    bounded_files_picker:typeof showSaveFilePicker==='function',persisted:await navigator.storage.persisted(),
    persist_granted:await navigator.storage.persist(),physical_acceptance:'NOT RUN until device trial is recorded'});}catch(error){show(error.message);}
};
document.querySelector('#storage').onclick=async()=>{try{show(await call({kind:'storage'}));}catch(error){show(error.message);}};
document.querySelector('#measure-kdf').onclick=async()=>{
  try{
    const {derived_hex,...measurement}=await call({kind:'kdf',request:{profile_version:1,algorithm:'argon2id13',
      phrase:'public synthetic strong phrase alpha',salt_hex:'000102030405060708090a0b0c0d0e0f',opslimit:3,memlimit:67108864}});
    show(measurement); // Never render a key, even though this vector is explicitly public.
  }catch(error){show(error.message);}
};
document.querySelector('#upload').onclick=async()=>{
  if(!source.files[0]){show('Select a synthetic file first.');return;}
  try{locked=false;show(await call({kind:'upload',source:source.files[0]}));}catch(error){show(error.message);}
};
document.querySelector('#reselect').onclick=async()=>{try{show(await call({kind:'reselect',source:source.files[0]}));}catch(error){show(error.message);}};
document.querySelector('#export').onclick=async()=>{
  if(locked){show('PAUSED_LOCKED: restart required.');return;}
  if(typeof showSaveFilePicker!=='function'){
    show('BLOCKED: this browser has no tested bounded Files export sink. OPFS and whole-file Blob download do not satisfy this gate.');return;
  }
  try{
    const sink=await showSaveFilePicker({suggestedName:'anynote-p01-synthetic-export.bin'});
    if(locked)throw new Error('Lifecycle invalidation during picker; restart required');
    show({...await call({kind:'export',sink}),sink:'File System Access explicit user-selected output',
      required:'Independently hash the actual saved file; desktop support does not prove iOS Files.'});
  }catch(error){show(error.message);}
};
document.querySelector('#prepare-share').onclick=async()=>{
  if(locked){show('PAUSED_LOCKED: restart required.');return;}
  try{if(prepared)await discardExport(prepared.id);prepared=await prepareExport(call);show(prepared);}
  catch(error){prepared=null;show(error.message);}
};
document.querySelector('#share').onclick=async()=>{
  if(!prepared||locked){show('Prepare a verified synthetic export first.');return;}
  sharing=true;
  try{show(await shareExport(prepared.id));}
  catch(error){show(error.message);}
  finally{if(prepared)await discardExport(prepared.id).catch(()=>{});sharing=false;prepared=null;}
};
document.querySelector('#cleanup-export').onclick=async()=>{try{prepared=null;show(await removeOrphans());}catch(error){show(error.message);}};
if('serviceWorker' in navigator)navigator.serviceWorker.register('/service-worker.js',{scope:'/physical/'}).catch(error=>show(`Installation unavailable: ${error.message}`));
globalThis.physicalP01={call,worker,prepareExport:()=>prepareExport(call),shareExport,discardExport,removeOrphans}; // Test-only hook.
