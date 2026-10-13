import Ajv from 'ajv/dist/2020.js';
import schemas from '../../contracts/generated/runtime-schemas.json' with {type:'json'};
import {formats} from '../auth-formats.mjs';
import {canonicalBytes} from '../adapters/core.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {decode,digest,domain} from '../adapters/codecs/protocol-codec.mjs';
import {sodium,b64,un64,hash,Buffer} from '../adapters/primitives.mjs';

const ensure=(condition,code)=>{if(!condition)throw Object.assign(Error(code),{code});};
const ajv=new Ajv({strict:true,ownProperties:true});for(const[k,v]of Object.entries(formats))ajv.addFormat(k,v);for(const s of schemas)ajv.addSchema(s);
const doc=schemas.find(s=>s.$id==='urn:anynote:p11:sync:v1');
const validators=new Map(Object.keys(doc.$defs).map(k=>[k,ajv.compile({$ref:doc.$id+'#/$defs/'+k})]));
export function syncValue(kind,value){ensure(validators.get(kind)?.(value),'INVALID_SYNC_DTO');return value;}
export const syncHash=value=>hash(canonicalBytes(wire(value)));
export function checkedScope(value,pins,group=null){syncValue('scope',value);ensure(value.service_id===pins.service_id&&value.account_id===pins.account_id&&value.root_fingerprint===pins.root_fingerprint&&value.group_id===group,'ROOT_PIN_MISMATCH');return value;}
export function checkedDelta(page,cursor,pins,group=null){
 syncValue('delta-page',page);checkedScope(page.scope,pins,group);decode('cursor',wire(cursor));ensure(same(page.from_cursor,cursor),'SYNC_CURSOR_EXPIRED');
 ensure(page.next_cursor.generation===cursor.generation&&page.watermark.generation===cursor.generation,'RESTORE_QUARANTINE');
 const from=BigInt(cursor.sequence),next=BigInt(page.next_cursor.sequence),high=BigInt(page.watermark.sequence);
 ensure(next>=from&&next<=high&&next-from===BigInt(page.scanned_count)&&BigInt(page.scanned_count)<=1000n,'SYNC_WATERMARK_MISMATCH');
 ensure(page.complete===(next===high)&&(next>from||page.complete),'SYNC_GAP');let last=from;const ids=new Set();
 for(const e of page.events){const n=BigInt(e.sequence);ensure(n>last&&n<=next&&!ids.has(e.event_id)&&(group===null||e.group_id===group),'SYNC_GAP');last=n;ids.add(e.event_id);}
 return page;
}
export function checkedSnapshot(result,pins,device,group=null){
 syncValue('snapshot-result',result);checkedScope(result.scope,pins,group);const d=decode('snapshot-descriptor',wire(result.descriptor));
 ensure(d.account_id===pins.account_id&&d.device_id===device&&d.snapshot_purpose==='resync'&&BigInt(d.expires_at)>BigInt(d.created_at)&&BigInt(d.expires_at)-BigInt(d.created_at)<=1800000n&&BigInt(d.page_count)<=8000n&&BigInt(d.item_count)<=50000n&&BigInt(result.catalog_count)<=1000n,'CONTEXT_MISMATCH');
 return result;
}
const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32BE(Number(n));return b;};
const u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(n));return b;};
export function snapshotCommitment(pages){
 const count=pages.reduce((n,p)=>n+BigInt(p.items),0n),chunks=[domain('hash','snapshot-inventory'),u32(pages.length),u64(count)];
 for(const p of pages)chunks.push(u32(p.index),u32(p.items),u32(p.bytes),un64(p.hash));
 return hash(Buffer.concat(chunks));
}
export function pageReceipt(page){decode('snapshot-page',wire(page));return {index:page.page_index,items:String(page.items.length),bytes:String(canonicalBytes(wire(page)).length),hash:digest('snapshot-page',wire(page))};}
export function catalogCommitment(groups){const parts=[Buffer.from('AnyNote/P11/catalog\0'),u32(groups.length)];for(const g of groups){const b=canonicalBytes(wire(g));parts.push(u32(b.length),b);}return hash(Buffer.concat(parts));}
export const itemOrder=item=>[item.group_id,item.object_kind,item.object_id,item.revision_id].join('/');
export function checkedBundle(item,bundle){
 decode('snapshot-item',wire(item));const b=decode('bundle',wire(bundle)),c=b.envelope.header.context;
 ensure(c.group_id===item.group_id&&c.object_id===item.object_id&&c.revision_id===item.revision_id&&c.object_kind===item.object_kind&&digest('envelope',wire(b.envelope))===item.envelope_digest,'CONTEXT_MISMATCH');
 const bytes=un64(b.ciphertext);ensure(String(bytes.length)===b.envelope.header.ciphertext_bytes&&hash(bytes)===b.envelope.header.ciphertext_digest&&digest('wrap',wire(b.wrap))===b.envelope.header.key_wrap_digest,'CIPHERTEXT_MISMATCH');
 ensure((c.action==='soft-delete')===(item.payload_status==='tombstone')&&item.payload_status!=='pruned','CONTEXT_MISMATCH');return b;
}
export const syncId=scope=>b64(un64(hash(Buffer.concat([Buffer.from('AnyNote/P11/sync-control\0'),canonicalBytes(wire(scope))]))).subarray(0,16));
