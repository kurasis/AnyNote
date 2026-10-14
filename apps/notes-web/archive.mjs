import {NotesClient} from '../../packages/protocol/notes/client.mjs';
import {ContentClient} from '../../packages/protocol/content/client.mjs';
import {encryptedBrowserSink} from '../../packages/protocol/files/browser-sink.mjs';
import {strictJson} from '../../packages/protocol/src/strict-json.mjs';
const element=(tag,id,key,text)=>{const node=document.createElement(tag);if(id)node.id=id;if(key){node.dataset.i18n=key;node.textContent=text(key);}return node;};
const ident=()=>btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
export function archiveUI({vault,plaintext,auth,files,getGroup,authorize,run,text}){
 const section=element('fieldset','portable-tools'),legend=element('legend',null,'portable_tools',text);section.append(legend);
 const toggle=(id,key,checked=false)=>{const input=element('input',id);input.type='checkbox';input.checked=checked;const label=element('label');label.append(input,element('span',null,key,text));section.append(label);return input;};
 const groupOnly=toggle('export-this-group','search_this_group',true),history=toggle('export-history','export_history'),trash=toggle('export-trash','export_trash');
 section.append(element('p',null,'export_committed_only',text));const start=element('button','portable-export','encrypted_export',text),state=element('p','portable-state');state.setAttribute('role','status');const kitSave=element('button','save-export-kit','save_separate_kit',text);kitSave.hidden=true;section.append(start,state,kitSave,element('p',null,'kit_separate_help',text));
 const input=(id,key)=>{const label=element('label');label.append(element('span',null,key,text));const node=element('input',id);node.type='file';label.append(node);section.append(label);return node;};
 const archive=input('import-archive','select_encrypted_archive'),kit=input('import-kit','select_separate_kit');const resume=element('input','resume-import-id');resume.maxLength=22;resume.autocomplete='off';resume.placeholder=text('resume_import_id');section.append(resume);
 const newPrivate=toggle('import-new-private','import_new_private',true);
 const inspect=element('button','inspect-import','inspect_import',text),audience=element('pre','import-audience'),confirmed=toggle('import-confirm','import_audience_confirm'),copy=element('button','copy-import','copy_import',text),cancel=element('button','cancel-import','cancel_import',text);section.append(inspect,audience,copy,cancel);document.getElementById('workspace').append(section);
 const plainConfirm=toggle('plaintext-confirm','plaintext_confirm'),plainSave=element('button','plaintext-export','plaintext_export',text);section.append(plainSave);
 plainSave.onclick=()=>run(async()=>{if(!plainConfirm.checked)throw Error('CONFIRMATION_REQUIRED');let payload=await plaintext();try{const data=JSON.stringify(payload,null,2)+'\n';if(data.length>1048576)throw Error('RESOURCE_LIMIT');const url=URL.createObjectURL(new Blob([data],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='anynote-note-'+payload.context.object_id+'.json';link.rel='noopener';link.click();setTimeout(()=>URL.revokeObjectURL(url),60000);plainConfirm.checked=false;}finally{clear(payload);}});
 const jobs=element('button','completed-content-jobs','completed_content_jobs',text),jobList=element('ul','content-job-list');section.append(jobs,jobList);jobs.onclick=()=>run(async()=>{jobList.replaceChildren();const {items}=await vault.notes('content',['jobs',{}]);for(const job of items){const li=element('li');li.textContent=job.job_id+' · '+job.state;if(job.retirable){const confirm=element('input');confirm.type='checkbox';const label=element('label');label.append(confirm,element('span',null,'retire_job_confirm',text));const remove=element('button',null,'retire_job',text);remove.onclick=()=>run(async()=>{await vault.notes('content',['retireJob',{job_id:job.job_id,confirm:confirm.checked}]);li.remove();});li.append(label,remove);}jobList.append(li);}});
 let generation=0,documentKit,prepared;
 const client=new ContentClient(auth),notes=new NotesClient(auth),command=(op,x={})=>vault.notes('import',[op,x]);
 function clear(value){if(value&&typeof value==='object')for(const key of Object.keys(value)){clear(value[key]);if(typeof value[key]==='string')value[key]='';}}
 kitSave.onclick=()=>{if(!documentKit)return;const url=URL.createObjectURL(new Blob([JSON.stringify(documentKit,null,2)+'\n'],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='anynote-'+documentKit.export_id+'.kit.json';link.rel='noopener';link.click();setTimeout(()=>URL.revokeObjectURL(url),60000);};
 start.onclick=()=>run(async()=>{
  const seen=generation;await authorize();const selected=groupOnly.checked?[getGroup()]:[];if(selected.some(x=>!x))throw Error('GROUP_REQUIRED');
  if(!groupOnly.checked)await authorize(null,true);const lease=await client.call('/exports','export-result',{version:1,operation_id:ident(),group_ids:selected.sort(),include_history:history.checked,include_trash:trash.checked});let sink,complete=false;
  clear(documentKit);documentKit=undefined;kitSave.hidden=true;
  try{const begun=await vault.notes('portable',['begin',{confirm:true,result:lease}]);sink=await encryptedBrowserSink('anynote-'+begun.export_id+'.age');
   for(;;){if(seen!==generation||document.hidden)throw Error('RESUME_REQUIRED');const frame=await vault.notes('portable',['next',{}]);if(frame.done){await sink.finish();documentKit=frame.kit;kitSave.hidden=false;state.textContent=text('encrypted_export_complete')+' '+frame.archive_bytes;complete=true;break;}try{await sink.write(frame.ciphertext);state.textContent=text('encrypted_export_progress')+' '+frame.archive_bytes;}finally{frame.ciphertext.fill(0);}}
  }finally{if(!complete){await sink?.abort().catch(()=>{});await vault.notes('portable',['cancel',{}]).catch(()=>{});}await client.call('/exports/'+lease.descriptor.snapshot_id,'cancel-result',undefined,'DELETE').catch(()=>{});}
 });
 inspect.onclick=()=>run(async()=>{
  const seen=generation;await authorize();if(!newPrivate.checked&&!getGroup()||!archive.files[0]||!kit.files[0])throw Error('SOURCE_IDENTITY_REQUIRED');if(kit.files[0].size>65536)throw Error('RESOURCE_LIMIT');
  const bytes=new Uint8Array(await kit.files[0].arrayBuffer());let independent;try{independent=strictJson(bytes,65536);prepared=await command('begin',{source:archive.files[0],kit:independent,...(newPrivate.checked?{}:{destination_group:getGroup()}),...(resume.value?{import_id:resume.value}:{})});}finally{bytes.fill(0);clear(independent);}
  if(seen!==generation)throw Error('RESUME_REQUIRED');resume.value=prepared.import_id;confirmed.checked=false;audience.textContent=text('import_preview')+'\n'+JSON.stringify(prepared.preview,null,2);state.textContent=text('import_ready');
 });
 copy.onclick=()=>run(async()=>{
  if(!prepared||!confirmed.checked)throw Error('COPY_CONFIRMATION_REQUIRED');const seen=generation;await command('confirm',{audience_digest:prepared.audience_digest});let response;
  for(;;){if(seen!==generation||document.hidden)throw Error('RESUME_REQUIRED');const step=await command('next',response?{response}:{});response=undefined;state.textContent=text('import_progress')+' '+step.published;
   if(step.state==='COMPLETE'){state.textContent=text('import_complete')+' '+step.published;prepared=undefined;confirmed.checked=false;break;}
   if(step.request){const r=step.request;if(r.kind==='group')response=await notes.call(r.path,'group-create','group-status',r.body);else if(r.kind==='file-part'){try{response=await files().transport.call(r.path,'PUT',r.ciphertext);}finally{r.ciphertext.fill(0);}}else if(r.kind==='note')response=await notes.call(r.path,'commit-request','receipt-result',r.body);else response=await files().transport.call(r.path,r.method,r.body);}
  }
 });
 cancel.onclick=()=>run(async()=>{const value=await command('cancel');state.textContent=text('import_cancelled')+' '+value.published;prepared=undefined;confirmed.checked=false;});
 return {close(){generation++;clear(documentKit);documentKit=undefined;prepared=undefined;kitSave.hidden=true;state.textContent='';audience.textContent='';confirmed.checked=false;plainConfirm.checked=false;jobList.replaceChildren();archive.value=kit.value='';},translate(){for(const node of section.querySelectorAll('[data-i18n]'))node.textContent=text(node.dataset.i18n);resume.placeholder=text('resume_import_id');}};
}
