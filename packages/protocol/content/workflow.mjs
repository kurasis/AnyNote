import {sodium, b64, Buffer} from '../adapters/primitives.mjs';
import {ensure, id} from '../vault/store.mjs';
import {coverage, indexDocument, searchDocument, searchFingerprint, SEARCH_LIMITS} from './search.mjs';

const random = () => b64(sodium.randombytes_buf(16));
const key = x => x.object_id + '/' + x.revision_id;
export function contentState(value) {
  ensure(value && value.purpose === 'p13-content-control' && value.version === 1 &&
    Array.isArray(value.pages) && value.pages.length <= 625 && Array.isArray(value.jobs) && value.jobs.length <= 32 &&
    (value.failures === undefined || Array.isArray(value.failures) && value.failures.length <= 10000 && value.failures.every(f => id(f.revision_id) && ['PAYLOAD_UNAVAILABLE','UNANCHORED_HISTORY','KEYS_PENDING'].includes(f.code))) &&
    value.pages.every(p => id(p.record_id) && typeof p.digest === 'string' && Array.isArray(p.documents) && p.documents.length <= 16 &&
      p.documents.every(d => id(d.group_id) && id(d.object_id) && id(d.revision_id) && typeof d.envelope_digest === 'string')), 'INVALID_CONTENT_CONTROL');
  ensure(new Set(value.pages.map(p => p.record_id)).size === value.pages.length &&
    new Set(value.pages.flatMap(p => p.documents.map(key))).size === value.pages.reduce((n, p) => n + p.documents.length, 0), 'DUPLICATE_RECORD');
  return value;
}
export function contentIds(control) {
  const result = new Map(control.pages.map(p => [p.record_id, 'search-page']));
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
  close() { wipe(this.#control); for (const value of this.#cache.values()) wipe(value.value); this.#cache.clear(); this.#cacheBytes = 0; this.#control = undefined; }
  async #ready() {
    const next = contentState(await this.load() ?? {purpose: 'p13-content-control', version: 1, pages: [], jobs: []});
    if (this.#control && searchFingerprint(next) !== searchFingerprint(this.#control)) this.close();
    this.#control = next;
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
    const failures=new Map((this.#control.failures??[]).map(f=>[f.revision_id,f.code]));
    const catalog = (await this.catalog()).filter(d => accessible.has(d.group_id) && (!x.group_id || d.group_id === x.group_id)).map(d=>({...d,payload_status:failures.get(d.revision_id)==='PAYLOAD_UNAVAILABLE'?'pruned':failures.get(d.revision_id)==='UNANCHORED_HISTORY'?'unanchored':d.payload_status}));
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
      ensure(!this.#control.source_stale || this.#control.pages.length === 0, 'INDEX_REBUILD_REQUIRED');
      ensure(Array.isArray(x.revision_ids) && x.revision_ids.length > 0 && x.revision_ids.length <= 16 && new Set(x.revision_ids).size === x.revision_ids.length, 'SEARCH_RESOURCE_LIMIT');
      const documents = [], skipped=[];
      for (const revision_id of x.revision_ids) {
        const expected = catalog.find(d => d.revision_id === revision_id); ensure(expected, 'RECORD_NOT_FOUND');
        let verified;try{verified=await this.open(revision_id);}catch(e){if(!['PAYLOAD_UNAVAILABLE','UNANCHORED_HISTORY','KEYS_PENDING'].includes(e.message))throw e;skipped.push({revision_id,code:e.message});continue;}
        try { ensure(verified.state === 'verified' && verified.envelope_digest === expected.envelope_digest, 'INTEGRITY_FAILURE');
          const document = indexDocument(verified.payload.context, verified.payload, verified.envelope_digest);
          ensure(document.group_id === expected.group_id && document.object_id === expected.object_id && document.revision_id === revision_id, 'CONTEXT_MISMATCH');
          documents.push(document); }
        finally { wipe(verified); }
      }
      this.#control.failures=[...(this.#control.failures??[]).filter(f=>!x.revision_ids.includes(f.revision_id)),...skipped];
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
          ({group_id: d.group_id, object_id: d.object_id, revision_id: d.revision_id, envelope_digest: d.envelope_digest, token_coverage: d.token_coverage}))});
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
