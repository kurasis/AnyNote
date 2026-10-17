// Streaming implementation of the frozen P02 USTAR profile. Never extracts paths.
import {generatedPath,entryCap,ARCHIVE_LIMIT} from '../src/archive-profile.mjs';
import {ensure} from '../vault/store.mjs';
import {Buffer,sodium,b64,hash} from '../adapters/primitives.mjs';
import {createHash} from '../adapters/bytes.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {common,decode,encode,digest,domain,signingInput} from '../adapters/codecs/protocol-codec.mjs';
const te=new TextEncoder(),td=new TextDecoder('utf-8',{fatal:true});
export const itemKind=path=>path.startsWith('identity/')?'identity':path.startsWith('keys/')?'key':path.startsWith('records/')?'record':path.startsWith('snapshots/')?'source-snapshot':'chunk';
export function tarHeader(path,size){
 ensure(generatedPath(path)&&Number.isSafeInteger(size)&&size>=0&&size<=entryCap(path),'INVALID_ARCHIVE_HEADER');
 const h=new Uint8Array(512),set=(s,at)=>h.set(te.encode(s),at),oct=(n,w)=>{const s=n.toString(8);ensure(s.length<w,'RESOURCE_LIMIT');return s.padStart(w-1,'0')+'\0';};
 set(path,0);set(oct(384,8),100);set(oct(0,8),108);set(oct(0,8),116);set(oct(size,12),124);set(oct(0,12),136);h.fill(32,148,156);h[156]=48;set('ustar\0',257);set('00',263);set(h.reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148);return h;
}
export async function* tarEntries(entries){
 let total=0n,count=0;
 for await(const {path,bytes}of entries){ensure(bytes instanceof Uint8Array,'RAW_BYTES_REQUIRED');ensure(++count<=4008003,'RESOURCE_LIMIT');const header=tarHeader(path,bytes.length),pad=(512-bytes.length%512)%512;total+=BigInt(512+bytes.length+pad);ensure(total+1024n<=ARCHIVE_LIMIT,'RESOURCE_LIMIT');yield header;yield bytes;if(pad)yield new Uint8Array(pad);}
 yield new Uint8Array(1024);
}
export async function parseTar(stream,visit){
 const it=stream[Symbol.asyncIterator]();let pending=new Uint8Array(),body,at=0,observed=0n,count=0,finished=false;
 async function read(n){ensure(n<=16777216,'RESOURCE_LIMIT');if(n>=1048576&&(!body||body.length<n))body=new Uint8Array(n);const result=n>=1048576?body.subarray(0,n):new Uint8Array(n);let written=0;while(written<n){if(at===pending.length){const next=await it.next();ensure(!next.done,'EXPORT_TRUNCATED');ensure(next.value instanceof Uint8Array&&next.value.length<=8388624,'RESOURCE_LIMIT');pending=next.value;at=0;observed+=BigInt(pending.length);ensure(observed<=ARCHIVE_LIMIT,'RESOURCE_LIMIT');if(!pending.length)continue;}const size=Math.min(n-written,pending.length-at);result.set(pending.subarray(at,at+size),written);at+=size;written+=size;}return result;}
 try{for(;;){const h=await read(512);if(h.every(v=>v===0)){ensure((await read(512)).every(v=>v===0),'INVALID_ARCHIVE_END');break;}const zero=h.indexOf(0);ensure(zero>0&&zero<=100,'UNSAFE_ARCHIVE_PATH');const path=td.decode(h.subarray(0,zero));ensure(generatedPath(path),'UNSAFE_ARCHIVE_PATH');const oct=td.decode(h.subarray(124,136));ensure(/^[0-7]{11}\0$/.test(oct),'INVALID_ARCHIVE_HEADER');const size=parseInt(oct,8);ensure(size<=entryCap(path)&&sodium.memcmp(h,tarHeader(path,size)),'INVALID_ARCHIVE_HEADER');ensure(++count<=4008003,'RESOURCE_LIMIT');const bytes=await read(size);ensure((await read((512-size%512)%512)).every(v=>v===0),'INVALID_ARCHIVE_PADDING');try{await visit({path,bytes});}finally{bytes.fill(0);}}
 ensure(at===pending.length,'TRAILING_ARCHIVE_DATA');for(;;){const next=await it.next();if(next.done)break;ensure(next.value instanceof Uint8Array&&next.value.length===0,'TRAILING_ARCHIVE_DATA');}finished=true;return {entries:count,observed_bytes:String(observed)};
 }finally{body?.fill(0);if(!finished)await it.return?.();pending.fill(0);}
}
// Same domain/framing as frozen P02; metadata cap is independent of file bytes.
export function pageCommitment(family,pages){
 ensure(['export','snapshot'].includes(family)&&pages.length<=8000,'RESOURCE_LIMIT');const decoded=pages.map(b=>decode(family+'-page',b)),count=decoded.reduce((n,p)=>n+p.items.length,0);ensure(count<=4000000,'RESOURCE_LIMIT');
 const frame=Buffer.alloc(12);frame.writeUInt32BE(pages.length);frame.writeBigUInt64BE(BigInt(count),4);const h=createHash('sha256').update(domain('hash',family+'-inventory')).update(frame);let last='';
 decoded.forEach((p,i)=>{ensure(p.page_index===String(i)&&p[family+'_id']===decoded[0][family+'_id']&&p.items.length>0,'INVALID_PAGE_ORDER');for(const row of p.items){const key=family==='export'?row.path:[row.group_id,row.object_kind,row.object_id,row.revision_id].join('/');ensure(key>last,'UNORDERED_OR_DUPLICATE');last=key;}if(i<decoded.length-1&&p.items.length<500)ensure(wire({...p,items:[...p.items,decoded[i+1].items[0]]}).length>1048576,'INVALID_PAGE_PACKING');const f=Buffer.alloc(12);f.writeUInt32BE(i);f.writeUInt32BE(p.items.length,4);f.writeUInt32BE(encode(family+'-page',pages[i]).length,8);h.update(f).update(Buffer.from(digest(family+'-page',pages[i]),'base64url'));});
 return {inventory_digest:h.digest('base64url'),page_count:String(pages.length),item_count:String(count)};
}
export async function* exportEntries(headerBytes,entries,signer,sign){
 const header=decode('export-header',headerBytes),pages=[];let batch=[],last='',total=0n,count=0,metadata=0;
 const flush=()=>{const bytes=encode('export-page',wire({...common('export-inventory-page'),export_id:header.export_id,page_index:String(pages.length),items:batch}));metadata+=bytes.length;ensure(metadata<=67108864&&pages.length<8000,'RESOURCE_LIMIT');pages.push(bytes);batch=[];};
 yield {path:'export-header.json',bytes:encode('export-header',headerBytes)};
 for await(const entry of entries){ensure(generatedPath(entry.path)&&entry.path>last&&!entry.path.startsWith('export-')&&!entry.path.startsWith('inventory/'),'UNORDERED_OR_DUPLICATE');last=entry.path;ensure(++count<=4000000,'RESOURCE_LIMIT');const row={path:entry.path,kind:itemKind(entry.path),size:String(entry.bytes.length),digest:hash(entry.bytes)};total+=BigInt(entry.bytes.length);batch.push(row);yield entry;if(batch.length===500)flush();}
 if(batch.length)flush();for(let i=0;i<pages.length;i++)yield {path:'inventory/'+String(i).padStart(8,'0')+'.json',bytes:pages[i]};
 const body={...common('export-footer'),export_id:header.export_id,header_digest:digest('export-header',headerBytes),...pageCommitment('export',pages),total_item_bytes:String(total),signer};
 yield {path:'export-footer.json',bytes:encode('export-footer',wire({body,signature:b64(await sign(signingInput('export-footer-body',wire(body))))}))};
}
