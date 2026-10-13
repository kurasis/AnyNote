import {SharedClient} from '../../packages/protocol/shared/client.mjs';
import {LocalVault} from '../../packages/protocol/vault/client.mjs';
import {profiles} from '../../packages/protocol/vault/registry.mjs';
import {AuthClient} from '../../packages/protocol/auth-client.mjs';
import {DevicesClient} from '../../packages/protocol/devices/client.mjs';
import {NotesClient} from '../../packages/protocol/notes/client.mjs';
import {renderMarkdown} from './markdown.mjs';
import {words} from './i18n.mjs';
const $=id=>document.getElementById(id);
let language=navigator.language.startsWith('ru')?'ru':'en',selected,groupSelected,threadSelected,editor,preferences=[],settingsGroup,settingsHeads=[],preferencesDraft,groupCursor=null,threadCursor=null,entryCursor=null,server=false,generation=0,editVersion=0,timer,tail=Promise.resolve(),pendingConflict;
const roles=new Map(),groups=new Map(),titles=new Map(),references=new Map();
const auth=new AuthClient(ANYNOTE_AUTH_ISSUER),devices=new DevicesClient(auth),api=new NotesClient(auth);
const sharing=new SharedClient(auth);
const text=k=>words[language][k]??words.en[k]??k;
const vault=new LocalVault('/auth/vault-worker.js',mask);
function erase(v){if(v&&typeof v==='object')for(const k of Object.keys(v)){if(typeof v[k]==='string')v[k]='';else erase(v[k]);}}
function mask(){
 generation++;clearTimeout(timer);editor&&erase(editor);editor=undefined;pendingConflict&&erase(pendingConflict);pendingConflict=undefined;
 roles.clear();groups.clear();titles.clear();references.clear();preferences=[];settingsGroup=undefined;groupSelected=threadSelected=undefined;server=false;
 $('workspace').hidden=true;$('unlock-panel').hidden=false;$('editor').hidden=true;$('conflict').hidden=true;
 for(const id of ['member-account','member-root','share-card','incoming-owner','incoming-device','phrase','group-title','thread-title','note-title','note-body','checklist-text','loaded-search'])$(id).value='';
 copyPrepared=undefined;for(const id of ['sharing-confirm','copy-confirm','close-account-confirm'])$(id).checked=false;for(const id of ['members-list','invitation-list','groups','threads','entries','drafts','checklist','preview','versions','trash-items'])$(id).replaceChildren();
 for(const id of ['membership-state','copy-audience','group-heading','thread-heading','thread-summary','audience','conflict-remote','save-state'])$(id).textContent='';
 $('lock-state').textContent=text('locked');$('status').textContent=text('locked');delete $('status').dataset.error;delete $('status').dataset.busy;
 for(const id of ['unlock','login','create-group','create-thread','save-note','save-local','refresh','retry'])$(id).disabled=false;
}
function translate(){
 document.documentElement.lang=language;$('language').value=language;
 for(const e of document.querySelectorAll('[data-i18n]'))e.textContent=text(e.dataset.i18n);
 $('lock-state').textContent=text($('workspace').hidden?'locked':'unlocked');
}
function reportError(e){
 const key=e.code??e.message??'NOTE_FAILURE';$('status').dataset.error=/^[A-Z_]+$/.test(key)?key:'NOTE_FAILURE';
 const messages={WRITER_BUSY:'writer_busy',KEYS_PENDING:'key_pending',KEY_REPAIR_REQUIRED:'key_repair',UNANCHORED_HISTORY:'unanchored',INTEGRITY_FAILURE:'integrity',CONTEXT_MISMATCH:'integrity',INVALID_SIGNATURE:'integrity',CIPHERTEXT_MISMATCH:'integrity',KEY_WRAP_MISMATCH:'integrity',ROLLBACK_QUARANTINE:'integrity',STORAGE_FAILURE:'storage',STORAGE_ABORTED:'storage',INSUFFICIENT_STORAGE:'storage',QUOTA_EXCEEDED:'quota',DEVICE_REVOKED:'revoked',SESSION_EXPIRED:'signed_out',AUTH_REQUIRED:'signed_out',ROLE_FORBIDDEN:roles.get(groupSelected)==='reader'?'reader_read_only':'role_forbidden',REKEY_REQUIRED:'blocked',HISTORY_CLOSURE_REQUIRED:'blocked',POLICY_CHANGED:'blocked',ROSTER_CHANGED:'blocked',STRONG_PHRASE_REQUIRED:'phrase_error',PROFILE_REQUIRED:'pick_profile',GROUP_REQUIRED:'not_ready',THREAD_REQUIRED:'not_ready',PUBLICATION_PENDING:'unknown',STALE_REVISION:'local_conflict'};
 $('status').textContent=text(messages[key]??'attention');
}
function run(action){
 const g=generation;
 const r=tail.then(async()=>{
  if(g!==generation)throw Error('STALE_CAPABILITY');
  delete $('status').dataset.error;$('status').dataset.busy='true';$('status').textContent=text('working');
  for(const id of ['unlock','login','create-group','create-thread','save-note','save-local','refresh','retry'])$(id).disabled=true;
  try{await action(g);if(g===generation&&!$('status').dataset.error)$('status').textContent=text('done');}
  catch(e){if(g===generation)reportError(e);throw e;}
  finally{if(g===generation){delete $('status').dataset.busy;for(const id of ['unlock','login','create-group','create-thread','save-note','save-local','refresh','retry'])$(id).disabled=false;}}
 });
 // UI failures are reported above, without a second unhandled rejection.
 tail=r.catch(()=>{});return tail;
}
function checkGeneration(g){if(g!==generation||document.hidden)throw Error('STALE_CAPABILITY');}
function savedState(state){$('save-state').dataset.state=state;$('save-state').textContent=text({SAVING:'saving',LOCAL_SAVED:'local',QUEUED:'local',SENT_UNKNOWN:'unknown',SYNCING:'syncing',COMMITTED:'synced',CONFLICT:'local_conflict'}[state]??'attention');}
function button(label,action){const e=document.createElement('button');e.type='button';e.textContent=label;e.onclick=()=>run(action);return e;}
function item(container,label,action,id){const li=document.createElement('li');if(id)li.dataset.id=id;li.append(button(label,action));container.append(li);}
function content(title='',markdown='',metadata_kind='content'){return {title,markdown,metadata_kind,tags:[],checklist:[],summary_entry_id:null,preferences:[]};}
function edit(group_id,kind,object_id=null,thread_id=null,fields=content(),parents=[],action=parents.length?'update':'create',archived=false){return {draft_id:null,group_id,object_id,object_kind:kind,thread_id,action,parents,archived,content:fields};}
function payloadContent(p){return {title:p.title,markdown:p.markdown,tags:p.tags,checklist:p.checklist,summary_entry_id:p.summary_entry_id,metadata_kind:p.metadata_kind,preferences:p.preferences};}
async function summary(){const s=await vault.notes('summary');$('drafts').replaceChildren();for(const d of s.drafts)item($('drafts'),text(d.state==='CONFLICT'?'local_conflict':'local')+' · '+d.object_kind,()=>openDraft(d.draft_id),d.draft_id);return s;}
async function loadLocal(){
 const s=await summary();for(const g of s.groups)groups.set(g.group_id,g.status??{group_id:g.group_id,settings:false,pending:true});
 for(const w of s.witnesses)references.set(w.object_id,{...w,heads:[{revision_id:w.revision_id,envelope_digest:w.envelope_digest}],tombstoned:w.action==='soft-delete'});
 for(const [id,r]of references)if(r.object_kind!=='entry'&&r.action!=='soft-delete'){try{const v=await vault.notes('cached',[r.revision_id]);titles.set(id,v.payload.title);}catch(e){if(e.message!=='RECORD_NOT_FOUND')throw e;}}
 renderGroups();
}
function renderGroups(){
 $('groups').replaceChildren();const q=$('loaded-search').value.toLocaleLowerCase();
 for(const [id,g]of [...groups].sort((a,b)=>preferenceOrder('group-order',a[0],b[0])))if(!g.settings){const name=titles.get(id)??text(g.pending?'pending_group':'pending_title');if(!q||name.toLocaleLowerCase().includes(q))item($('groups'),(preferences.some(p=>p.key==='favorite'&&p.target_id===id&&p.value==='1')?'★ ':'')+name,()=>openGroup(id),id);}
}
async function login(){await auth.ceremony('login');server=false;}
async function prove(){
 const me=await auth.call('/me',null,'me-result');if(me.session.account_id!==selected.account_id)throw Error('ACCOUNT_MISMATCH');
 const r=await auth.call('/auth/device-challenge','device-challenge-request','challenge-result',{version:1,device_id:selected.device_id}),proof=await vault.proof(r.challenge,me.session.id);
 await auth.call('/auth/device-proof','device-proof-request','auth-result',{version:1,challenge_id:r.challenge.context.challenge_id,proof});await devices.sync(vault,selected.account_id);server=true;
 const roster=await vault.devices('summary');$('key-target').replaceChildren();for(const d of roster.devices)if(d.status==='ACTIVE'&&d.device_id!==selected.device_id){const o=document.createElement('option');o.value=d.device_id;o.textContent=d.device_id;$('key-target').append(o);}
}
async function keyFor(status){
 if(status.kind==='shared'||status.key_epoch!=='0'){await shared('keys',{group_id:status.group_id}).catch(async e=>{if(e.message!=='ROSTER_CHANGED')throw e;});return;}

 let cursor=null,count=0,found=[];
 do{const part=await devices.call('/me/device-envelopes'+(cursor?'?after='+cursor:''),null,'envelope-result');count+=part.records.length;if(count>660)throw Error('RESOURCE_LIMIT');found.push(...part.records.filter(r=>r.body.context.group_id===status.group_id&&r.body.context.key_epoch==='0'));cursor=part.next;if(found.length)break;}while(cursor!==null);
 if(found.length)await vault.devices('acceptKeys',[status.genesis,found]);
}
async function groupStatus(id){if(!server)return groups.get(id);let g;try{g=await api.call('/groups/'+id,null,'group-status');}catch(e){if(e.message==='NOT_FOUND'){groups.delete(id);renderGroups();if(groupSelected===id){editor&&erase(editor);editor=undefined;$('editor').hidden=true;$('preview').replaceChildren();$('entries').replaceChildren();$('threads').replaceChildren();$('group-heading').textContent='';$('thread-heading').textContent='';$('audience').textContent=text('access_lost');}}throw e;}if(g.kind==='shared'||g.key_epoch!=='0')await sharedProof(id);await vault.notes('group',[g]);groups.set(id,g);return g;}
async function openRevision(group,ref,head){
 const result=await api.call('/objects/'+ref.object_id+'/revisions/'+head.revision_id,null,'bundle-result');
 if(result.group_id!==group||result.object_id!==ref.object_id||result.revision_id!==head.revision_id)throw Error('CONTEXT_MISMATCH');
 const opened=await vault.notes('open',[{group_id:group,object_id:ref.object_id,revision_id:head.revision_id,object_kind:ref.object_kind,thread_id:ref.thread_id,bundle:result.bundle}]);
 if(opened.envelope_digest!==head.envelope_digest)throw Error('INTEGRITY_FAILURE');return opened;
}
async function fetchPayload(group,ref){if(server)return openRevision(group,ref,ref.heads[0]);const s=await summary(),w=s.witnesses.findLast(w=>w.group_id===group&&w.object_id===ref.object_id);if(!w)throw Error('KEYS_PENDING');return vault.notes('cached',[w.revision_id]);}
async function loadGroups(more=false){
 const page=await api.call('/groups'+(more&&groupCursor?'?after='+groupCursor:''),null,'groups-page');groupCursor=page.next;$('more-groups').hidden=groupCursor===null;
 for(const g of page.groups){if(g.kind==='shared'||g.key_epoch!=='0'){try{await sharedProof(g.group_id);}catch(e){if(e.message==='KEYS_PENDING'){groups.set(g.group_id,g);continue;}throw e;}}await vault.notes('group',[g]);groups.set(g.group_id,g);if(g.settings)settingsGroup=g.group_id;
  try{await keyFor(g);const state=await api.call('/objects/'+g.group_id,null,'object-state');references.set(g.group_id,{group_id:g.group_id,...state.object});const opened=await openRevision(g.group_id,state.object,state.object.heads[0]);titles.set(g.group_id,opened.payload.title);if(g.settings){preferences=opened.payload.preferences;settingsHeads=state.object.heads;}}
  catch(e){if(!['NOT_FOUND','KEYS_PENDING'].includes(e.message))throw e;}
 }renderGroups();await summary();
}
async function refresh(){await prove();await loadGroups();await copyDestinations();if(groupSelected&&groups.has(groupSelected))await openGroup(groupSelected);await retryPending();await summary();}
async function openGroup(id){
 clearTimeout(timer);await flushIfDirty();groupSelected=id;threadSelected=undefined;const g=await groupStatus(id);if(!g)throw Error('GROUP_REQUIRED');
 $('group-heading').textContent=titles.get(id)??text('pending_title');$('audience').textContent=text(g.state==='archived'?'archived':g.kind==='shared'?'shared_group':'private');$('thread-heading').textContent='';$('entries').replaceChildren();$('editor').hidden=true;$('threads').replaceChildren();threadCursor=null;
 if(server){await keyFor(g);await loadThreads();}else for(const [object,r]of references)if(r.group_id===id&&r.object_kind==='thread'&&!r.tombstoned)item($('threads'),titles.get(object)??text('untitled'),()=>openThread(object),object);
}
async function loadThreads(more=false){
 if(!groupSelected)throw Error('GROUP_REQUIRED');const page=await api.call('/groups/'+groupSelected+'/threads'+(more&&threadCursor?'?after='+threadCursor:''),null,'objects-page');
 if(page.group_id!==groupSelected||page.thread_id!==null)throw Error('CONTEXT_MISMATCH');threadCursor=page.next;$('more-threads').hidden=threadCursor===null;if(!more)$('threads').replaceChildren();
 for(const ref of [...page.objects].sort((a,b)=>preferenceOrder('thread-order',a.object_id,b.object_id))){references.set(ref.object_id,{group_id:groupSelected,...ref});const opened=await openRevision(groupSelected,ref,ref.heads[0]);titles.set(ref.object_id,opened.payload.title);item($('threads'),(ref.archived?'▣ ':'')+(opened.payload.title||text('untitled')),()=>openThread(ref.object_id),ref.object_id);}
}
async function openThread(id){
 await flushIfDirty();threadSelected=id;const ref=references.get(id);if(!ref||ref.group_id!==groupSelected||ref.object_kind!=='thread')throw Error('CONTEXT_MISMATCH');
 $('thread-heading').textContent=titles.get(id)??text('untitled');$('entries').replaceChildren();$('editor').hidden=true;entryCursor=null;
 await threadSummary(ref);if(server)await loadEntries();else for(const [object,r]of references)if(r.group_id===groupSelected&&r.thread_id===id&&!r.tombstoned)item($('entries'),titles.get(object)??text('untitled'),()=>openEntry(object),object);
}
function preferenceOrder(key,a,b){const order=id=>BigInt(preferences.find(p=>p.key===key&&p.target_id===id)?.value??'9223372036854775807');return order(a)<order(b)?-1:order(a)>order(b)?1:a<b?-1:1;}
async function threadSummary(ref){
 $('thread-summary').textContent='';const opened=await fetchPayload(groupSelected,ref),id=opened.payload.summary_entry_id;if(id===null)return;
 const state=server?await api.call('/objects/'+id,null,'object-state'):{group_id:groupSelected,object:references.get(id)};
 if(!state.object||state.group_id!==groupSelected||state.object.object_kind!=='entry'||state.object.thread_id!==ref.object_id)throw Error('CONTEXT_MISMATCH');
 if(state.object.tombstoned)return;const entry=await fetchPayload(groupSelected,state.object);$('thread-summary').textContent=entry.payload.title;
}
async function loadEntries(more=false){
 if(!threadSelected)throw Error('THREAD_REQUIRED');const page=await api.call('/threads/'+threadSelected+'/entries'+(more&&entryCursor?'?after='+entryCursor:''),null,'objects-page');
 if(page.group_id!==groupSelected||page.thread_id!==threadSelected)throw Error('CONTEXT_MISMATCH');entryCursor=page.next;$('more-entries').hidden=entryCursor===null;if(!more)$('entries').replaceChildren();
 for(const ref of page.objects){if(ref.object_kind!=='entry'||ref.thread_id!==threadSelected)throw Error('CONTEXT_MISMATCH');references.set(ref.object_id,{group_id:groupSelected,...ref});item($('entries'),titles.get(ref.object_id)??text('untitled'),()=>openEntry(ref.object_id),ref.object_id);}
}
function showEditor(value,state='LOCAL_SAVED'){
 editor=structuredClone(value);editVersion=0;$('editor').hidden=false;$('conflict').hidden=true;$('versions').replaceChildren();$('note-title').value=editor.content.title;$('note-body').value=editor.content.markdown;drawChecklist();renderMarkdown($('preview'),editor.content.markdown);savedState(state);
}
async function openEntry(id){
 await flushIfDirty();const ref=references.get(id);if(!ref||ref.group_id!==groupSelected||ref.thread_id!==threadSelected)throw Error('CONTEXT_MISMATCH');
 const opened=await fetchPayload(groupSelected,ref),p=opened.payload;if(p.context.action==='soft-delete')throw Error('NOT_FOUND');titles.set(id,p.title);showEditor(edit(groupSelected,'entry',id,threadSelected,payloadContent(p),ref.heads),'COMMITTED');
}
function capture(){if(!editor)throw Error('DRAFT_NOT_FOUND');const e=structuredClone(editor);e.content.title=$('note-title').value;e.content.markdown=$('note-body').value;return e;}
function drawChecklist(){
 $('checklist').replaceChildren();for(const item of editor?.content.checklist??[]){const li=document.createElement('li'),box=document.createElement('input'),label=document.createElement('label');box.type='checkbox';box.checked=item.checked;box.id='check-'+item.item_id;label.htmlFor=box.id;label.textContent=item.text;box.onchange=()=>{item.checked=box.checked;dirty();};li.append(box,label);$('checklist').append(li);}
}
function dirty(){editVersion++;savedState('SAVING');clearTimeout(timer);timer=setTimeout(()=>{run(()=>flushLocal()).catch(()=>{});},500);try{renderMarkdown($('preview'),$('note-body').value);}catch(e){reportError(e);}}
async function flushLocal(){
 if(!editor)return null;const version=editVersion,e=capture(),identity=editor;savedState('SAVING');
 try{const saved=await vault.notes('save',[e]);if(editor===identity){editor.draft_id=saved.draft_id;editor.object_id=saved.object_id;if(version===editVersion){editor.content=structuredClone(e.content);editVersion=0;savedState('LOCAL_SAVED');}}await summary();return saved;}finally{erase(e);}
}
async function flushIfDirty(){clearTimeout(timer);if(editor&&editVersion>0)await flushLocal();}
async function openDraft(id){
 await flushIfDirty();const d=await vault.notes('draft',[id]),p=d.payload;groupSelected=p.context.group_id;threadSelected=p.context.thread_id;
 $('group-heading').textContent=titles.get(groupSelected)??text('pending_title');$('thread-heading').textContent=threadSelected?(titles.get(threadSelected)??text('untitled')):'';
 showEditor({...edit(groupSelected,p.context.object_kind,p.context.object_id,threadSelected,payloadContent(p),p.context.parents,p.context.action,p.context.archived),draft_id:id});
}
async function submitDraft(draft_id){
 const state=await vault.notes('summary'),pending=state.drafts.find(d=>d.draft_id===draft_id&&['QUEUED','SENT_UNKNOWN'].includes(d.state));const queued=pending?{attempt_id:pending.attempt_id,state:pending.state}:await vault.notes('queue',[draft_id]);let sent;savedState('SYNCING');
 try{
  const known=queued.state==='SENT_UNKNOWN'?await api.receipt(queued.attempt_id).catch(e=>{if(e.message!=='NOT_FOUND')throw e;return null;}):null;
  let result=known;if(!result){sent=await vault.notes('send',[queued.attempt_id]);result=await api.publish(sent.request);}
  const ack=await vault.notes('ack',[queued.attempt_id,result]);await summary();
  if(editor?.draft_id===draft_id){if(ack.draft_retired){editor.draft_id=null;editor.action='update';editor.parents=result.heads;savedState(editVersion>0?'SAVING':'COMMITTED');}else{const local=await vault.notes('draft',[draft_id]);editor.parents=local.payload.context.parents;editor.action=local.payload.context.action;savedState('LOCAL_SAVED');}}
  const witness=(await vault.notes('summary')).witnesses.find(w=>w.revision_id===ack.revision_id);
  if(!witness)throw Error('INTEGRITY_FAILURE');references.set(witness.object_id,{...witness,heads:result.heads,tombstoned:witness.action==='soft-delete'});return result;
 }catch(e){
  if(['STALE_REVISION','REKEY_REQUIRED','HISTORY_CLOSURE_REQUIRED','POLICY_CHANGED','ROSTER_CHANGED','DEVICE_REVOKED','DEVICE_NOT_TRUSTED','ROLE_FORBIDDEN','NOT_FOUND','ACCESS_REVOKED'].includes(e.message)){await vault.notes('reject',[queued.attempt_id,e.message]);savedState(e.message==='STALE_REVISION'?'CONFLICT':'NEEDS_ATTENTION');if(e.message==='STALE_REVISION'&&editor?.draft_id===draft_id)await showConflict();}else savedState('SENT_UNKNOWN');throw e;
 }
}
async function saveNote(){if(!editor)throw Error('DRAFT_NOT_FOUND');if(!editor.draft_id||editVersion>0)await flushLocal();if(!server)await prove();const g=await groupStatus(editor.group_id);await keyFor(g);await submitDraft(editor.draft_id);}
async function saveFields(e){const saved=await vault.notes('save',[e]);await summary();await submitDraft(saved.draft_id);return saved;}
async function createGroup(){
 const title=$('group-title').value;if(!title.trim())throw Error('INVALID_REQUEST');const kind=$('group-kind').value;let phase='prepare-group';
 try{
  const made=await vault.notes(kind==='shared'?'prepareShared':'prepareGroup');phase='save-metadata';const local=await vault.notes('save',[edit(made.group_id,'group-metadata',made.group_id,null,content(title))]);phase='local-summary';await summary();groups.set(made.group_id,{group_id:made.group_id,pending:true,settings:false});titles.set(made.group_id,title);renderGroups();
  phase='create-genesis';const status=await api.call('/groups','group-create','group-status',made.request);phase='accept-genesis';await vault.notes('group',[status]);groups.set(status.group_id,status);
  if(kind==='shared'){groupSelected=status.group_id;phase='prepare-history';await shared('history',{group_id:status.group_id});phase='commit-history';await accessChange(status.group_id);phase='verify-history';await sharedProof(status.group_id);phase='refresh-status';await vault.notes('group',[await api.call('/groups/'+status.group_id,null,'group-status')]);}
  phase='publish-metadata';await submitDraft(local.draft_id);$('group-title').value='';phase='open-group';await openGroup(made.group_id);delete $('status').dataset.phase;
 }catch(e){$('status').dataset.phase=phase;throw e;}
}

async function createThread(){
 if(!groupSelected)throw Error('GROUP_REQUIRED');const title=$('thread-title').value;if(!title.trim())throw Error('INVALID_REQUEST');
 const saved=await saveFields(edit(groupSelected,'thread',null,null,content(title)));titles.set(saved.object_id,title);$('thread-title').value='';await loadThreads();await openThread(saved.object_id);
}
async function retryPending(){
 const s=await vault.notes('summary');
 for(const g of s.groups)if(g.state==='GENESIS_PENDING'){const r=await vault.notes('retryGroup',[g.group_id]);const status=await api.call('/groups','group-create','group-status',r.request);await vault.notes('group',[status]);groups.set(g.group_id,status);}
 for(const d of s.drafts)if(d.state==='QUEUED'||d.state==='SENT_UNKNOWN'||(d.state==='LOCAL_SAVED'&&d.object_kind==='group-metadata'&&s.groups.some(g=>g.group_id===d.group_id&&g.state==='GENESIS_PENDING')))await submitDraft(d.draft_id);
}
async function showConflict(){
 const state=await api.call('/objects/'+editor.object_id,null,'object-state'),opened=await openRevision(editor.group_id,state.object,state.object.heads[0]);pendingConflict={heads:state.object.heads,payload:opened.payload};$('conflict-remote').textContent=opened.payload.title+'\n\n'+opened.payload.markdown;$('conflict').hidden=false;
}
async function versions(){
 if(!editor?.object_id)throw Error('DRAFT_NOT_FOUND');await flushIfDirty();const page=await api.call('/objects/'+editor.object_id+'/revisions',null,'revisions-page');$('versions').replaceChildren();
 for(const r of page.revisions)item($('versions'),text('saved_version')+' · '+r.revision_id.slice(-8),async()=>{
  const ref={object_id:editor.object_id,object_kind:editor.object_kind,thread_id:editor.thread_id,heads:[r]},opened=await openRevision(editor.group_id,ref,r);$('conflict-remote').textContent=opened.payload.title+'\n\n'+opened.payload.markdown;
  const li=document.createElement('li');li.append(button(text('restore'),async()=>{const current=await api.call('/objects/'+editor.object_id,null,'object-state');await openRevision(editor.group_id,current.object,current.object.heads[0]);showEditor(edit(editor.group_id,editor.object_kind,editor.object_id,editor.thread_id,payloadContent(opened.payload),current.object.heads,current.object.tombstoned?'restore':'update'));dirty();}));$('versions').append(li);
 },r.revision_id);
}
async function trash(){
 if(!groupSelected)throw Error('GROUP_REQUIRED');await flushIfDirty();const page=await api.call('/groups/'+groupSelected+'/trash',null,'objects-page');$('trash-items').replaceChildren();
 for(const ref of page.objects){const tomb=await openRevision(groupSelected,ref,ref.heads[0]);item($('trash-items'),text('restore')+' · '+ref.object_id.slice(-8),async()=>{
  const parent=tomb.payload.context.parents[0];if(!parent)throw Error('INTEGRITY_FAILURE');const old=(await openRevision(groupSelected,ref,parent)).payload;
  if(old.context.action==='soft-delete')throw Error('INTEGRITY_FAILURE');await saveFields(edit(groupSelected,ref.object_kind,ref.object_id,ref.thread_id,payloadContent(old),ref.heads,'restore'));await trash();if(threadSelected)await loadEntries();
 },ref.object_id);}
}
async function updatePreferences(change){
 if(!groupSelected||!settingsGroup)throw Error('GROUP_REQUIRED');const g=await groupStatus(settingsGroup);await keyFor(g);
 const current=await api.call('/objects/'+settingsGroup,null,'object-state').catch(e=>{if(e.message!=='NOT_FOUND')throw e;return null;});
 if(current){const p=await openRevision(settingsGroup,current.object,current.object.heads[0]);preferences=p.payload.preferences;settingsHeads=current.object.heads;}else settingsHeads=[];
 change();preferences.sort((a,b)=>(a.key+'/'+a.target_id)<(b.key+'/'+b.target_id)?-1:1);
 const fields=content('','','account-preferences');fields.preferences=preferences;const saved=await vault.notes('save',[{...edit(settingsGroup,'group-metadata',settingsGroup,null,fields,settingsHeads),draft_id:preferencesDraft??null}]);preferencesDraft=saved.draft_id;await submitDraft(saved.draft_id);preferencesDraft=undefined;renderGroups();
}
function putPreference(key,target_id,value){preferences=preferences.filter(p=>!(p.key===key&&p.target_id===target_id));preferences.push({key,target_id,value});}
async function favorite(){await updatePreferences(()=>{const old=preferences.find(p=>p.key==='favorite'&&p.target_id===groupSelected);putPreference('favorite',groupSelected,old?.value==='1'?'0':'1');});}
async function moveFirst(key,id,ids){if(!id)throw Error('GROUP_REQUIRED');await updatePreferences(()=>{[id,...ids.filter(x=>x!==id)].forEach((x,n)=>putPreference(key,x,String(n)));});if(key==='thread-order')await loadThreads();}
async function rename(kind){
 const id=kind==='group-metadata'?groupSelected:threadSelected;if(!id)throw Error('GROUP_REQUIRED');
 const state=await api.call('/objects/'+id,null,'object-state'),opened=await openRevision(groupSelected,state.object,state.object.heads[0]),title=kind==='group-metadata'?$('group-title').value:$('thread-title').value;if(!title.trim())throw Error('INVALID_REQUEST');
 const fields=payloadContent(opened.payload);fields.title=title;await saveFields(edit(groupSelected,kind,id,null,fields,state.object.heads,'update',state.object.archived));titles.set(id,title);renderGroups();if(kind==='thread')await loadThreads();else $('group-heading').textContent=title;
}
$('language').onchange=()=>{language=$('language').value;translate();renderGroups();};
$('lock').onclick=()=>{clearTimeout(timer);vault.lock().catch(reportError);};
$('login').onclick=()=>run(login);
$('profiles').onchange=()=>run(async()=>{await vault.lock();selected=JSON.parse($('profiles').value);await vault.open(selected);});
$('unlock').onclick=()=>run(async g=>{
 if(!selected)throw Error('PROFILE_REQUIRED');const phrase=$('phrase').value;$('phrase').value='';await vault.unlock(phrase);checkGeneration(g);$('workspace').hidden=false;$('unlock-panel').hidden=true;$('lock-state').textContent=text('unlocked');await loadLocal();
 try{await refresh();}catch(e){if(['AUTH_REQUIRED','SESSION_EXPIRED','TEMPORARY_UNAVAILABLE'].includes(e.message)||e.name==='TypeError'){$('status').textContent=text('local_only');server=false;}else throw e;}
});
$('refresh').onclick=()=>run(refresh);$('retry').onclick=()=>run(async()=>{await prove();await retryPending();await summary();});
$('create-group-form').onsubmit=e=>{e.preventDefault();run(createGroup);};$('create-thread-form').onsubmit=e=>{e.preventDefault();run(createThread);};
$('more-groups').onclick=()=>run(()=>loadGroups(true));$('more-threads').onclick=()=>run(()=>loadThreads(true));$('more-entries').onclick=()=>run(()=>loadEntries(true));
$('loaded-search').oninput=renderGroups;
$('new-entry').onclick=()=>run(async()=>{await flushIfDirty();if(!groupSelected||!threadSelected)throw Error('THREAD_REQUIRED');showEditor(edit(groupSelected,'entry',null,threadSelected));$('note-title').focus();});
$('note-title').oninput=dirty;$('note-body').oninput=dirty;
$('add-checklist').onclick=()=>{if(!editor)return;const value=$('checklist-text').value;if(!value.trim())return;const bytes=crypto.getRandomValues(new Uint8Array(16)),item_id=btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');editor.content.checklist.push({item_id,text:value,checked:false});editor.content.checklist.sort((a,b)=>a.item_id<b.item_id?-1:1);$('checklist-text').value='';drawChecklist();dirty();};
$('editor').onsubmit=e=>{e.preventDefault();clearTimeout(timer);run(saveNote);};$('save-local').onclick=()=>{clearTimeout(timer);run(flushLocal);};
$('delete-note').onclick=()=>run(async()=>{await flushIfDirty();if(!editor?.object_id)throw Error('DRAFT_NOT_FOUND');const state=await api.call('/objects/'+editor.object_id,null,'object-state');await openRevision(editor.group_id,state.object,state.object.heads[0]);await saveFields(edit(editor.group_id,editor.object_kind,editor.object_id,editor.thread_id,content(),state.object.heads,'soft-delete'));editor=undefined;$('editor').hidden=true;$('preview').replaceChildren();if(threadSelected)await loadEntries();});
$('group-first').onclick=()=>run(()=>moveFirst('group-order',groupSelected,[...groups].filter(([,g])=>!g.settings).map(([id])=>id)));
$('thread-first').onclick=()=>run(()=>moveFirst('thread-order',threadSelected,[...references.values()].filter(r=>r.group_id===groupSelected&&r.object_kind==='thread').map(r=>r.object_id)));
$('mark-read').onclick=()=>run(async()=>{if(!threadSelected)throw Error('THREAD_REQUIRED');const values=[...references.values()].filter(r=>r.group_id===groupSelected&&r.thread_id===threadSelected).map(r=>BigInt(r.updated_sequence??'0'));await updatePreferences(()=>putPreference('read-marker',threadSelected,String(values.reduce((a,b)=>a>b?a:b,0n))));});
$('history').onclick=()=>run(versions);$('trash').onclick=()=>run(trash);$('favorite').onclick=()=>run(favorite);
$('rename-group').onclick=()=>run(()=>rename('group-metadata'));$('rename-thread').onclick=()=>run(()=>rename('thread'));
$('archive-thread').onclick=()=>run(async()=>{if(!threadSelected)throw Error('THREAD_REQUIRED');const state=await api.call('/objects/'+threadSelected,null,'object-state'),opened=await openRevision(groupSelected,state.object,state.object.heads[0]);await saveFields(edit(groupSelected,'thread',threadSelected,null,payloadContent(opened.payload),state.object.heads,'update',!state.object.archived));await loadThreads();});
$('pin-summary').onclick=()=>run(async()=>{await saveNote();const state=await api.call('/objects/'+threadSelected,null,'object-state'),opened=await openRevision(groupSelected,state.object,state.object.heads[0]),fields=payloadContent(opened.payload);fields.summary_entry_id=editor.object_id;await saveFields(edit(groupSelected,'thread',threadSelected,null,fields,state.object.heads));await threadSummary(references.get(threadSelected));});
$('resolve-conflict').onclick=()=>run(async()=>{if(!editor||!pendingConflict)throw Error('CONFLICT_REQUIRED');editor.parents=pendingConflict.heads;editor.action='update';$('conflict').hidden=true;pendingConflict=undefined;dirty();await flushLocal();$('status').textContent=text('review');});
$('keep-both').onclick=()=>run(async()=>{if(!editor||editor.object_kind!=='entry')throw Error('CONFLICT_REQUIRED');const e=capture();e.draft_id=null;e.object_id=null;e.action='create';e.parents=[];showEditor(e);dirty();await saveNote();});
$('send-group-keys').onclick=()=>run(async()=>{if(!groupSelected)throw Error('GROUP_REQUIRED');const target=$('key-target').value;if(!target)throw Error('INVALID_REQUEST');await devices.sync(vault,selected.account_id);let request;if(groups.get(groupSelected)?.kind==='shared'){await sharedProof(groupSelected);request=await shared('ownGrants',{group_id:groupSelected,device_id:target});}else{const evidence=await vault.notes('groupEvidence',[groupSelected]),grant=await vault.devices('distribute',[evidence,target,null,true]);request=grant.request;}await devices.call('/me/device-envelopes','envelope-request','cancel-result',request);$('status').textContent=text('key_done');});
$('offline').onclick=()=>run(async()=>{if(!navigator.serviceWorker)throw Error('STORAGE_UNAVAILABLE');await navigator.serviceWorker.register('/auth/sw.js',{scope:'/auth/'});await navigator.serviceWorker.ready;$('status').textContent=text('offline_done');});
async function start(){translate();const list=await profiles();$('profiles').replaceChildren();for(const p of list){const o=document.createElement('option');o.value=JSON.stringify(p);o.textContent=p.account_id.slice(-8)+' · '+p.device_id.slice(-8);$('profiles').append(o);}if(!list.length){$('empty').hidden=false;return;}selected=list[0];await vault.open(selected);$('status').dataset.state='ready';}
start().catch(reportError);

const shared=(op,x)=>vault.notes('shared',[op,x]);
async function sharedProof(id){
 let proof=await shared('proof',{group_id:id});const journal=await sharing.call('/groups/'+id+'/journal',null,'journal');
 const accounts=[];for(const a of proof.accounts)accounts.push({pins:a.pins,snapshot:await devices.snapshot(a.pins.account_id,a.pins.root_fingerprint)});
 proof={...proof,journal,accounts};const checked=await shared('adopt',proof);roles.set(id,checked.members.find(m=>m.account_id===selected.account_id)?.role);return proof;
}
async function accessChange(id){
 const a=await shared('retry',{group_id:id}),r=a.body.invitation??a.body.acceptance??a.body.policy??a.body.intent??a.body.commit??a.body.history,op=r?.body.operation_id??a.body.operation_id;let result=await sharing.call('/me/group-receipts/'+op+'?family='+(a.family==='epoch'?'commit':a.family),null,'result').catch(e=>{if(e.message!=='NOT_FOUND')throw e;return null;});
 if(result){await shared('complete',{group_id:id,result});return result;}
 if(a.family==='epoch'){
  await sharing.call('/groups/'+id+'/epoch/begin','begin-request','result',a.body);
  for(const page of a.pages)await sharing.call('/groups/'+id+'/epoch/page','page-request','result',{version:1,page});
  result=await sharing.call('/groups/'+id+'/epoch/commit','commit-request','result',{version:1,commit:a.commit});
 }else result=await sharing.call('/groups/'+id+'/'+({invite:'invites',consent:'owner-consent'}[a.family]??a.family),{invite:'invitation-request',consent:'policy-request',policy:'policy-request',accept:'accept-request',history:'history-request',cancel:'cancel-request'}[a.family],'result',a.body);
 await shared('complete',{group_id:id,result});return result;
}
async function members(){
 if(!groupSelected||!server)throw Error('GROUP_REQUIRED');const g=groups.get(groupSelected);if(g.kind==='private'){await vault.notes('shared',['upgradePrivate',{group_id:groupSelected}]).catch(e=>{if(e.message!=='GROUP_PROOF_REQUIRED')throw e;});}
 const proof=await sharedProof(groupSelected),state=await shared('details',{group_id:groupSelected});$('members-list').replaceChildren();$('membership-state').textContent=text({WRITABLE:'shared_ready',REKEY_REQUIRED:'blocked',HISTORY_CLOSURE_REQUIRED:'blocked',UNANCHORED_HISTORY:'unanchored',ARCHIVED:'archived'}[state.write_state]??'attention');
 for(const m of state.members){const li=document.createElement('li');li.textContent=m.account_id+' · '+text({owner:'owner',reader:'reader',editor:'editor_role'}[m.role]);li.dataset.account=m.account_id;
  if(m.role!=='owner'&&roles.get(groupSelected)==='owner'){
   li.append(button(text(m.role==='reader'?'make_editor':'make_reader'),async()=>{if(!$('sharing-confirm').checked)throw Error('CONFIRMATION_REQUIRED');await shared('policy',{group_id:groupSelected,action:'role',target_account_id:m.account_id,role:m.role==='reader'?'editor':'reader',confirm:true});await accessChange(groupSelected);await members();}));
   li.append(button(text('remove_member'),async()=>{if(!$('sharing-confirm').checked)throw Error('CONFIRMATION_REQUIRED');await shared('policy',{group_id:groupSelected,action:'remove',target_account_id:m.account_id,confirm:true});await accessChange(groupSelected);await members();}));
  }$('members-list').append(li);
 }return {proof,state};
}
async function importCard(accept=false){
 if(!$('sharing-confirm').checked)throw Error('CONFIRMATION_REQUIRED');let proof;try{proof=JSON.parse($('share-card').value);}catch{throw Error('INVALID_SHARED_DTO');}
 if(proof.pin?.owner_root_fingerprint!==$('member-root').value.trim())throw Error('ROOT_PIN_MISMATCH');
 const own={pins:{service_id:selected.service_id,account_id:selected.account_id,root_fingerprint:(await vault.devices('summary')).pins.root_fingerprint},snapshot:await devices.snapshot(selected.account_id)};
 const known=proof.accounts.find(a=>a.pins.account_id===selected.account_id);if(known){if(known.pins.root_fingerprint!==own.pins.root_fingerprint)throw Error('ROOT_PIN_MISMATCH');known.snapshot=own.snapshot;}else proof.accounts.push(own);
 await shared('adopt',proof);groupSelected=proof.pin.group_id;
 if(accept){const invite=proof.journal.pending?.invitation;if(!invite)throw Error('INVITATION_REQUIRED');const pending=await sharing.call('/me/group-invitations',null,'invitations-page');if(!pending.invitations.some(i=>i.body.operation_id===invite.body.operation_id&&i.signature===invite.signature))throw Error('INVITATION_REQUIRED');await shared('accept',{group_id:groupSelected,invitation:invite,confirm:true});await accessChange(groupSelected);$('membership-state').textContent=text('pending_grants');}
 else{await sharedProof(groupSelected);const status=await api.call('/groups/'+groupSelected,null,'group-status');await vault.notes('group',[status]);groups.set(groupSelected,status);await keyFor(status);await loadGroups();}
}
async function showInvitations(){const p=await sharing.call('/me/group-invitations',null,'invitations-page');$('invitation-list').replaceChildren();for(const i of p.invitations){const li=document.createElement('li');li.textContent=i.body.group_id+' · '+text(i.body.role==='reader'?'reader':'editor_role')+' · '+text('invitation_help');$('invitation-list').append(li);}}
let copyPrepared;
async function previewCopy(){
 if(!editor?.object_id||!server)throw Error('DRAFT_NOT_FOUND');const state=await api.call('/objects/'+editor.object_id,null,'object-state');const head=state.object.heads[0];await openRevision(editor.group_id,state.object,head);
 const [destination_group,destination_thread]=$('copy-destination').value.split('/');if(!destination_group||!destination_thread)throw Error('GROUP_REQUIRED');await groupStatus(destination_group);
 copyPrepared={source_group:editor.group_id,destination_group,destination_thread,revision_id:head.revision_id};const preview=await vault.notes('copyPreview',[copyPrepared]);copyPrepared.preview_digest=preview.digest;$('copy-audience').textContent=text('copy_scope')+' '+preview.preview.destination_audience.map(m=>m.account_id+' ('+text({owner:'owner',reader:'reader',editor:'editor_role'}[m.role])+')').join(', ');$('copy-confirm').checked=false;
}
async function copyDestinations(){
 $('copy-destination').replaceChildren();for(const [id,g]of groups)if(g.kind==='shared'){const p=await api.call('/groups/'+id+'/threads',null,'objects-page');for(const t of p.objects){const option=document.createElement('option');option.value=id+'/'+t.object_id;option.textContent=(titles.get(id)??text('shared_group'))+' / '+(titles.get(t.object_id)??text('untitled'));$('copy-destination').append(option);}}
}
$('invitations').onclick=()=>run(showInvitations);
$('members-panel').ontoggle=()=>{if($('members-panel').open&&groupSelected&&server)run(members);};
$('invite-member').onclick=()=>run(async()=>{const account=$('member-account').value.trim(),root=$('member-root').value.trim();await members();const a={pins:{service_id:selected.service_id,account_id:account,root_fingerprint:root},snapshot:await devices.snapshot(account,root)};await shared('invite',{group_id:groupSelected,account:a,expected_root:root,role:$('member-role').value,confirm:$('sharing-confirm').checked});await accessChange(groupSelected);await members();$('share-card').value=JSON.stringify(await shared('card',{group_id:groupSelected}));});
$('activate-member').onclick=()=>run(async()=>{await members();await shared('epoch',{group_id:groupSelected,reason:'admission',confirm:$('sharing-confirm').checked});await accessChange(groupSelected);await members();await groupStatus(groupSelected);await keyFor(groups.get(groupSelected));});
$('close-history').onclick=()=>run(async()=>{await members();await shared('history',{group_id:groupSelected});await accessChange(groupSelected);await members();await groupStatus(groupSelected);});
$('maintain-keys').onclick=()=>run(async()=>{const {proof}=await members();const old=proof.journal.events.findLast(e=>e.kind==='epoch')?.commit??proof.journal.genesis.commit,epochVersion=old.body.intent.body.membership.version,removed=proof.journal.events.some(e=>e.kind==='policy'&&e.policy.body.action==='remove'&&BigInt(e.policy.body.version)>BigInt(epochVersion));await shared('epoch',{group_id:groupSelected,reason:removed?'member-removal':'roster-maintenance',confirm:true});await accessChange(groupSelected);await members();await groupStatus(groupSelected);await keyFor(groups.get(groupSelected));});
$('optional-rekey').onclick=()=>run(async()=>{await members();await shared('epoch',{group_id:groupSelected,reason:'optional',confirm:true});await accessChange(groupSelected);await members();});
$('retry-membership').onclick=()=>run(async()=>{await accessChange(groupSelected);await members();});
$('show-share-card').onclick=()=>run(async()=>{await members();$('share-card').value=JSON.stringify(await shared('card',{group_id:groupSelected}));});
$('accept-invitation').onclick=()=>run(()=>importCard(true));$('import-group').onclick=()=>run(()=>importCard(false));
$('archive-group').onclick=()=>run(async()=>{const {state}=await members();await shared('policy',{group_id:groupSelected,action:state.write_state==='ARCHIVED'?'unarchive':'archive',confirm:$('sharing-confirm').checked});await accessChange(groupSelected);await members();await groupStatus(groupSelected);});
$('propose-owner').onclick=()=>run(async()=>{await members();$('share-card').value=JSON.stringify(await shared('transferProposal',{group_id:groupSelected,account_id:$('incoming-owner').value,device_id:$('incoming-device').value,confirm:$('sharing-confirm').checked}));});
$('consent-owner').onclick=()=>run(async()=>{await login();await prove();await members();const a=await shared('cosign',{group_id:groupSelected,policy:JSON.parse($('share-card').value),confirm:$('sharing-confirm').checked});await accessChange(groupSelected);$('share-card').value=JSON.stringify(a.body.policy);});
$('finish-owner').onclick=()=>run(async()=>{await login();await prove();await members();await shared('transfer',{group_id:groupSelected,policy:JSON.parse($('share-card').value),confirm:$('sharing-confirm').checked});await accessChange(groupSelected);await members();});
$('copy-preview').onclick=()=>run(previewCopy);$('copy-entry').onclick=()=>run(async()=>{if(!copyPrepared||!$('copy-confirm').checked)throw Error('COPY_CONFIRMATION_REQUIRED');await groupStatus(copyPrepared.destination_group);const d=await vault.notes('copy',[{...copyPrepared,confirm:true}]);await submitDraft(d.draft_id);copyPrepared=undefined;$('copy-audience').textContent=text('copy_done');await summary();});

$('cancel-membership').onclick=()=>run(async()=>{const body=await shared('cancelAttempt',{group_id:groupSelected,confirm:$('sharing-confirm').checked});const result=await sharing.call('/groups/'+groupSelected+'/cancel','cancel-request','result',body);await shared('finishCancel',{group_id:groupSelected,result});await members();});

$('close-account').onclick=()=>run(async()=>{if(!$('close-account-confirm').checked)throw Error('CONFIRMATION_REQUIRED');await login();await prove();const pins=(await vault.devices('summary')).pins,operation_id=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');await sharing.call('/me/close-account','account-close-request','account-close-result',{version:1,account_id:selected.account_id,root_fingerprint:pins.root_fingerprint,operation_id,confirmation:'CLOSE_ACCOUNT'});server=false;await vault.lock();});
