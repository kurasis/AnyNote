import {sodium, b64, Buffer} from '../adapters/primitives.mjs';
import {envelopeDigest} from '../adapters/codecs/codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {ensure, id} from '../vault/store.mjs';
import {coverage, indexDocument, searchDocument, searchFingerprint, SEARCH_LIMITS} from './search.mjs';

const random = () => b64(sodium.randombytes_buf(16));
const key = x => [x.group_id,x.object_kind,x.object_id,x.revision_id].join('/');
export function contentState(value) {
  ensure(value && value.purpose === 'p13-content-control' && value.version === 1 &&
    Array.isArray(value.pages) && value.pages.length <= 688 && Array.isArray(value.jobs) && value.jobs.length <= 32 &&
    (value.files===undefined||Array.isArray(value.files)&&value.files.length<=1000&&value.files.every(f=>id(f.record_id)&&id(f.file_version_id)&&id(f.file_id)&&id(f.group_id)&&typeof f.envelope_digest==='string')) &&
    (value.failures === undefined || Array.isArray(value.failures) && value.failures.length <= 10000 && value.failures.every(f => id(f.revision_id) && ['PAYLOAD_UNAVAILABLE','UNANCHORED_HISTORY','KEYS_PENDING'].includes(f.code))) &&
    value.pages.every(p => id(p.record_id) && typeof p.digest === 'string' && Array.isArray(p.documents) && p.documents.length <= 16 &&
      p.documents.every(d => id(d.group_id) && id(d.object_id) && id(d.revision_id) && typeof d.envelope_digest === 'string')), 'INVALID_CONTENT_CONTROL');
  ensure(new Set(value.pages.map(p => p.record_id)).size === value.pages.length &&
    new Set(value.pages.flatMap(p => p.documents.map(key))).size === value.pages.reduce((n, p) => n + p.documents.length, 0), 'DUPLICATE_RECORD');
  return value;
}
export function contentIds(control) {
  const result = new Map(control.pages.map(p => [p.record_id, 'search-page']));
  for(const file of control.files??[]){ensure(!result.has(file.record_id),'DUPLICATE_RECORD');result.set(file.record_id,'file-metadata');}
  for (const job of control.jobs) {
    ensure(id(job.record_id) && ['export-state', 'import-state', 'preview-state'].includes(job.kind) && !result.has(job.record_id), 'INVALID_CONTENT_CONTROL');
    result.set(job.record_id, job.kind);
  }
  return result;
}
function wipe(value) {
  if (value instanceof Uint8Array) sodium.memzero(value);
  else if (value && typeof value === 'object') for (const k of Object.keys(value)) { wipe(value[k]); if (typeof value[k] === 'string') value[k] = ''; }
}
export class ContentWorkflow {
  #control; #cache = new Map(); #cacheBytes = 0;
  constructor({load, read, persist, catalog, accessible, open}) { Object.assign(this, {load, read, persist, catalog, accessible, open}); }
  fileReferences(){return structuredClone(this.#control?.files??[]);}
  // Internal custody coordinators only; no generic job read/write command exists.
  async job(job_id,kind){await this.#ready();ensure(id(job_id)&&['export-state','import-state','preview-state'].includes(kind),'INVALID_CONTENT_RECORD');const ref=this.#control.jobs.find(j=>j.record_id===job_id&&j.kind===kind);ensure(ref,'RECORD_NOT_FOUND');return this.read(ref.record_id,kind);}
  async saveJob(job_id,kind,data){await this.#ready();ensure(id(job_id)&&['export-state','import-state','preview-state'].includes(kind),'INVALID_CONTENT_RECORD');const ref=this.#control.jobs.find(j=>j.record_id===job_id);ensure(!ref||ref.kind===kind,'INVALID_CONTENT_RECORD');if(!ref){ensure(this.#control.jobs.length<32,'RESOURCE_LIMIT');this.#control.jobs.push({record_id:job_id,kind});}try{await this.persist(this.#control,[{id:job_id,kind,data}]);}finally{this.close();}}
  close() { wipe(this.#control); for (const value of this.#cache.values()) wipe(value.value); this.#cache.clear(); this.#cacheBytes = 0; this.#control = undefined; }
  async #ready() {
    const next = contentState(await this.load() ?? {purpose: 'p13-content-control', version: 1, pages: [], jobs: []});
    if (this.#control && searchFingerprint(next) !== searchFingerprint(this.#control)) this.close();
    this.#control = next;
  }
  async rememberFile(record) {
    await this.#ready();const c=record.envelope.header.context,digest=envelopeDigest(wire(record.envelope));
    this.#control.files??=[];const previous=this.#control.files.find(f=>f.file_version_id===c.file_version_id);
    if(previous){ensure(previous.envelope_digest===digest&&previous.group_id===c.group_id,'ROLLBACK_QUARANTINE');return;}
    ensure(this.#control.files.length<1000,'RESOURCE_LIMIT');const record_id=random();
    this.#control.files.push({record_id,group_id:c.group_id,file_id:c.file_id,file_version_id:c.file_version_id,envelope_digest:digest});
    this.#control.failures=(this.#control.failures??[]).filter(f=>f.revision_id!==c.file_version_id);
    try{await this.persist(this.#control,[{id:record_id,kind:'file-metadata',data:{purpose:'p13-file-metadata',version:1,record}}]);}finally{this.close();}
  }
  async fileRecord(revision) {
    await this.#ready();const ref=this.#control.files?.find(f=>f.file_version_id===revision);ensure(ref,'PAYLOAD_UNAVAILABLE');
    const data=await this.read(ref.record_id,'file-metadata');ensure(data.purpose==='p13-file-metadata'&&data.version===1&&envelopeDigest(wire(data.record.envelope))===ref.envelope_digest,'INTEGRITY_FAILURE');
    return data.record;
  }
  async #page(ref) {
    let value = this.#cache.get(ref.record_id)?.value;
    if (!value) {
      value = await this.read(ref.record_id, 'search-page');
      ensure(value.purpose === 'p13-search-page' && value.version === 1 && Array.isArray(value.documents) &&
        value.documents.length === ref.documents.length && value.documents.length <= 16 && searchFingerprint(value) === ref.digest &&
        value.documents.every((d, n) => key(d) === key(ref.documents[n]) && d.envelope_digest === ref.documents[n].envelope_digest), 'INTEGRITY_FAILURE');
      const bytes = Buffer.byteLength(JSON.stringify(value));
      while (this.#cacheBytes + bytes > 33554432 && this.#cache.size) {
        const [first, old] = this.#cache.entries().next().value; this.#cache.delete(first); this.#cacheBytes -= old.bytes; wipe(old.value);
      }
      if (bytes <= 33554432) { this.#cache.set(ref.record_id, {value, bytes}); this.#cacheBytes += bytes; }
    } else { const old = this.#cache.get(ref.record_id); this.#cache.delete(ref.record_id); this.#cache.set(ref.record_id, old); }
    return value;
  }
  async command(op, x = {}) {
    await this.#ready(); const accessible = await this.accessible();
    ensure(x.group_id === undefined || accessible.has(x.group_id), 'ROLE_FORBIDDEN');
    if(op==='jobs'){const items=[];for(const ref of this.#control.jobs){const value=await this.read(ref.record_id,ref.kind);items.push({job_id:ref.record_id,kind:ref.kind,state:value.state??'PREPARED',retirable:ref.kind==='import-state'&&value.state==='COMPLETE'||ref.kind==='preview-state'&&value.state==='LINKED'});}return {items,limit:32};}
    if(op==='retireJob'){ensure(x.confirm===true&&id(x.job_id),'CONFIRMATION_REQUIRED');const ref=this.#control.jobs.find(j=>j.record_id===x.job_id);ensure(ref,'RECORD_NOT_FOUND');const value=await this.read(ref.record_id,ref.kind);ensure(ref.kind==='import-state'&&value.state==='COMPLETE'||ref.kind==='preview-state'&&value.state==='LINKED','UNSYNCED_WORK_PROTECTED');this.#control.jobs=this.#control.jobs.filter(j=>j!==ref);try{await this.persist(this.#control,[],[ref.record_id]);return {retired:true,publication_journals_preserved:true};}finally{this.close();}}
    const failures=new Map((this.#control.failures??[]).map(f=>[f.revision_id,f.code]));
    const catalog = (await this.catalog()).filter(d => accessible.has(d.group_id) && (!x.group_id || d.group_id === x.group_id)).map(d=>({...d,payload_status:failures.get(d.revision_id)==='PAYLOAD_UNAVAILABLE'?'unavailable':failures.get(d.revision_id)==='UNANCHORED_HISTORY'?'unanchored':failures.get(d.revision_id)==='KEYS_PENDING'?'keys-pending':d.payload_status}));
    const indexed = this.#control.pages.flatMap(p => p.documents).filter(d => accessible.has(d.group_id) && (!x.group_id || d.group_id === x.group_id));
    const report = () => {const value=coverage(catalog,indexed,accessible);if(this.#control.source_stale){value.stale+=value.indexed;value.indexed=0;}return {...value,rebuild_required:this.#control.source_stale===true,scope:x.group_id??'accessible-account',known_corpus_only:true};};
    if(op==='catalog'){const start=x.after??0;ensure(Number.isSafeInteger(start)&&start>=0&&start<=catalog.length,'INVALID_SEARCH_QUERY');const items=catalog.slice(start,start+100).map(d=>({group_id:d.group_id,object_id:d.object_id,revision_id:d.revision_id,object_kind:d.object_kind,payload_status:d.payload_status,current:d.current}));return {items,next:start+items.length<catalog.length?start+items.length:null,known:catalog.length,known_corpus_only:true};}
    if (op === 'coverage') return report();
    if (op === 'clearIndex') {
      ensure(x.confirm === true && x.group_id === undefined, 'CONFIRMATION_REQUIRED');
      const removed = this.#control.pages.filter(p => !x.group_id || p.documents.some(d => d.group_id === x.group_id));
      this.#control.pages = this.#control.pages.filter(p => !removed.includes(p));
      this.#control.failures=[];
      await this.persist(this.#control, [], removed.map(p => p.record_id)); this.close();
      return {cleared_pages: removed.length, remote_content_preserved: true, pending_work_preserved: true};
    }
    if (op === 'index') {
      ensure(!this.#control.source_stale || this.#control.pages.length === 0, 'INDEX_REBUILD_REQUIRED');this.#control.source_stale=false;
      const selectors=x.items??x.revision_ids;
      ensure(Array.isArray(selectors)&&selectors.length>0&&selectors.length<=16&&new Set(selectors.map(s=>typeof s==='string'?s:key(s))).size===selectors.length,'SEARCH_RESOURCE_LIMIT');
      const documents = [], skipped=[];
      for (const selector of selectors) {
        const expected = catalog.find(d => typeof selector==='string'?d.revision_id===selector:key(d)===key(selector)); ensure(expected, 'RECORD_NOT_FOUND');const revision_id=expected.revision_id;
        let verified;try{verified=await this.open(expected);}catch(e){if(!['PAYLOAD_UNAVAILABLE','UNANCHORED_HISTORY','KEYS_PENDING'].includes(e.message))throw e;skipped.push({revision_id,code:e.message});continue;}
        try { ensure(verified.state === 'verified' && verified.envelope_digest === expected.envelope_digest, 'INTEGRITY_FAILURE');
          const document = indexDocument(verified.payload.context, verified.payload, verified.envelope_digest);
          ensure(document.group_id === expected.group_id && document.object_id === expected.object_id && document.revision_id === revision_id, 'CONTEXT_MISMATCH');
          documents.push(document); }
        finally { wipe(verified); }
      }
      const revisions=selectors.map(s=>typeof s==='string'?s:s.revision_id);this.#control.failures=[...(this.#control.failures??[]).filter(f=>!revisions.includes(f.revision_id)),...skipped];
      const replaced = new Set(documents.map(key)), old = this.#control.pages.filter(p => p.documents.some(d => replaced.has(key(d))));
      const partial = this.#control.pages.find(p => p.documents.length < 16 && !old.includes(p));
      if (partial) old.push(partial);
      const remaining = [];
      for (const ref of old) remaining.push(...(await this.#page(ref)).documents.filter(d => !replaced.has(key(d))).map(d => structuredClone(d)));
      this.#control.pages = this.#control.pages.filter(p => !old.includes(p));
      const records = [], all = [...remaining, ...documents];
      for (let n = 0; n < all.length; n += 16) {
        const data = {purpose: 'p13-search-page', version: 1, documents: all.slice(n, n + 16)}, record_id = random();
        this.#control.pages.push({record_id, digest: searchFingerprint(data), documents: data.documents.map(d =>
          ({group_id: d.group_id, object_id: d.object_id, revision_id: d.revision_id, object_kind:d.object_kind,envelope_digest: d.envelope_digest, token_coverage: d.token_coverage}))});
        records.push({id: record_id, kind: 'search-page', data});
      }
      ensure(this.#control.pages.flatMap(p => p.documents).length <= SEARCH_LIMITS.documents, 'SEARCH_RESOURCE_LIMIT');
      const count=documents.length;
      try{contentState(this.#control); await this.persist(this.#control, records, old.map(p => p.record_id));}
      finally{for(const record of records)wipe(record.data);this.close();}
      return {indexed: count, skipped, storage: 'protected-local-only'};
    }
    if (op === 'search') {
      ensure(typeof x.query === 'string' && x.query.length > 0 && x.query.length <= 256, 'INVALID_SEARCH_QUERY');
      if(this.#control.source_stale)return {results:[],coverage:report(),rebuild_required:true,scope:x.group_id??'accessible-account',known_corpus_only:true};
      const current = new Map(catalog.map(d => [key(d), d])), results = [];
      for (const ref of this.#control.pages) {
        if (!ref.documents.some(d => current.has(key(d)))) continue;
        const page = await this.#page(ref);
        for (const document of page.documents) {
          const expected = current.get(key(document));
          if (!expected || expected.envelope_digest !== document.envelope_digest || !accessible.has(document.group_id)) continue;
          if (x.include_history !== true && expected.current === false) continue;
          if (searchDocument(document, x.query)) results.push({group_id: document.group_id, object_id: document.object_id,
            revision_id: document.revision_id, thread_id: document.thread_id, object_kind: document.object_kind,
            title: document.title, snippet: document.snippet, historical: expected.current === false, head_status:expected.current===null?'unknown':'known',payload_status: expected.payload_status});
          if (results.length === SEARCH_LIMITS.results) break;
        }
        if (results.length === SEARCH_LIMITS.results) break;
      }
      return {results, coverage: report(), limit: SEARCH_LIMITS.results,
        truncated: results.length === SEARCH_LIMITS.results, scope: x.group_id ?? 'accessible-account', known_corpus_only: true};
    }
    throw Error('INVALID_CONTENT_COMMAND');
  }
}
