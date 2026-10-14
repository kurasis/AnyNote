// Runs only inside protected custody. The host receives age ciphertext and a separate independent kit.
import {independentExportIdentity,encryptArchive,streamFromIterator} from '../../content-browser/age.mjs';
import {tarEntries,exportEntries,pageCommitment} from './archive.mjs';
import {contentValue} from './client.mjs';
import {common,encode} from '../adapters/codecs/protocol-codec.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {createHash} from '../adapters/bytes.mjs';
import {catalogCommitment} from '../sync/codec.mjs';
import {ensure,id} from '../vault/store.mjs';
import {b64,sodium,hash} from '../adapters/primitives.mjs';
const random=()=>b64(sodium.randombytes_buf(16)),index=i=>String(i).padStart(8,'0');
export class ProtectedExport{
 #transport;#reader;#identity;#kit;#digest=createHash('sha256');#closed=false;#bytes=0n;#authorize;
 constructor({transport,authorize,scope,pins,signer,sign,proofs,selected,verifyChunk}){Object.assign(this,{scope,pins,signer,sign,proofs,selected,verifyChunk});this.#transport=transport;this.#authorize=authorize;}
 async begin(input){
  const lease=contentValue('export-result',input);ensure(lease.scope.service_id===this.scope.service_id&&lease.scope.account_id===this.scope.account_id&&lease.scope.root_fingerprint===this.pins.root_fingerprint&&lease.descriptor.device_id===this.scope.device_id&&lease.descriptor.snapshot_purpose==='export','LOCAL_CONTEXT_MISMATCH');
  ensure(BigInt(lease.descriptor.page_count)<=8000n&&BigInt(lease.descriptor.item_count)<=51000n&&BigInt(lease.catalog_count)<=1000n,'RESOURCE_LIMIT');
  const path='/exports/'+lease.descriptor.snapshot_id,groups=[];let start=0;
  do{const page=contentValue('catalog-page',await this.#transport.get(path+'/catalog?start='+start));ensure(page.snapshot_id===lease.descriptor.snapshot_id&&page.start===String(start),'EXPORT_SOURCE_MISMATCH');groups.push(...page.groups);ensure(groups.length<=200,'RESOURCE_LIMIT');if(page.next===null)break;ensure(Number(page.next)===start+page.groups.length&&page.groups.length>0,'INVALID_PAGE_ORDER');start=Number(page.next);}while(start<1000);
  ensure(String(groups.length)===lease.catalog_count&&catalogCommitment(groups)===lease.catalog_digest&&new Set(groups.map(g=>g.group_id)).size===groups.length,'EXPORT_SOURCE_MISMATCH');
  const pages=[],items=[];for(let i=0;i<Number(lease.descriptor.page_count);i++){const result=contentValue('export-page-result',await this.#transport.get(path+'/pages?start='+i));ensure(result.page.snapshot_id===lease.descriptor.snapshot_id&&same(result.scope,lease.scope),'EXPORT_SOURCE_MISMATCH');pages.push(wire(result.page));items.push(...result.page.items);}
  ensure(same(pageCommitment('snapshot',pages),{page_count:lease.descriptor.page_count,item_count:lease.descriptor.item_count,inventory_digest:lease.descriptor.inventory_digest}),'EXPORT_SOURCE_MISMATCH');
  // Complete public proof and selected-key preparation never runs in the renderer.
  const headers=[];start=0;do{const page=contentValue('export-header-page',await this.#transport.get(path+'/headers?start='+start));ensure(page.snapshot_id===lease.descriptor.snapshot_id&&page.start===String(start),'EXPORT_SOURCE_MISMATCH');headers.push(...page.items);ensure(headers.length<=items.length,'EXPORT_SOURCE_MISMATCH');if(page.next===null)break;ensure(Number(page.next)===start+page.items.length&&page.items.length>0,'INVALID_PAGE_ORDER');start=Number(page.next);}while(start<51000);
  ensure(headers.length===items.length&&headers.every((h,n)=>same(h.item,items[n])),'EXPORT_SOURCE_MISMATCH');
  const evidence=await this.proofs(groups,headers);
  await this.#authorize();this.#identity=await independentExportIdentity();const export_id=random(),header={...common('export-header'),export_id,service_id:this.scope.service_id,account_id:this.scope.account_id,root_fingerprint:this.pins.root_fingerprint,snapshot:lease.descriptor,selection:{group_ids:groups.map(g=>g.group_id).sort(),include_history:lease.selection.include_history,include_trash:lease.selection.include_trash},created_at:lease.descriptor.created_at,outer_format:'age-v1-X25519',archive_format:'ustar-anynote-v1'};
  this.#kit={...common('export-recovery-document'),export_id,exporter_root_fingerprint:this.pins.root_fingerprint,exporter_roster:this.signer.roster,independent_group_pins:evidence.pins};
  const transport=this.#transport,selected=this.selected,authorize=this.#authorize,verifyChunk=this.verifyChunk;
  const sorted=[...items].sort((a,b)=>a.revision_id<b.revision_id?-1:1);
  async function* entries(){
   for(const item of sorted.filter(i=>i.object_kind==='file-manifest'&&i.payload_status!=='pruned')){await authorize();const response=contentValue('export-record-result',await transport.get(path+'/records/'+item.revision_id));ensure(same(response.item,item),'EXPORT_SOURCE_MISMATCH');const record=response.record;
    // Constructor verification/key preparation authenticates the signed manifest
    // before it can drive any chunk URL or resource allocation.
    const key=await selected(item,record);key.object_dek='';key.file_data_dek='';
    for(let n=0;n<Number(record.envelope.header.framing.chunk_count);n++){const bytes=await transport.get(path+'/files/'+item.revision_id+'/chunks/'+n,true),part=record.envelope.header.framing.parts[n];ensure(hash(bytes)===part.ciphertext_digest&&String(bytes.length)===part.ciphertext_bytes,'CHUNK_DIGEST_MISMATCH');await verifyChunk(item,record,n,bytes);yield {path:'files/'+item.revision_id+'/'+index(n)+'.bin',bytes};}
   }
   yield {path:'identity/evidence.json',bytes:wire(evidence.document)};
   for(const item of sorted.filter(i=>i.payload_status!=='pruned')){await authorize();const response=contentValue('export-record-result',await transport.get(path+'/records/'+item.revision_id));ensure(same(response.item,item),'EXPORT_SOURCE_MISMATCH');const key=await selected(item,response.record);try{yield {path:'keys/'+item.revision_id+'.json',bytes:encode('export-key',wire(key))};}finally{key.object_dek='';key.file_data_dek='';}}
   for(const item of sorted){await authorize();const response=contentValue('export-record-result',await transport.get(path+'/records/'+item.revision_id));ensure(same(response.item,item),'EXPORT_SOURCE_MISMATCH');yield {path:'records/'+item.revision_id+'.json',bytes:encode(item.payload_status==='pruned'?'export-pruned-record':item.object_kind==='file-manifest'?'export-file-record':'bundle',wire(response.record))};}
   for(let i=0;i<pages.length;i++)yield {path:'snapshots/'+index(i)+'.json',bytes:pages[i]};
  }
  this.#reader=(await encryptArchive(streamFromIterator(tarEntries(exportEntries(wire(header),entries(),this.signer,this.sign)),this.#authorize),this.#identity.recipient)).getReader();return {export_id,recipient:this.#identity.recipient,lease_maximum_expires_at_ms:lease.maximum_expires_at_ms,selection:header.selection};
 }
 async next(){ensure(this.#reader&&!this.#closed,'EXPORT_NOT_STARTED');await this.#authorize();const value=await this.#reader.read();await this.#authorize();if(value.done){const kit={...this.#kit,archive_sha256:this.#digest.digest('base64url'),export_identity:this.#identity.identity};this.#identity.identity='';this.#closed=true;this.#reader.releaseLock();this.#reader=undefined;return {done:true,kit,archive_bytes:String(this.#bytes)};}ensure(value.value instanceof Uint8Array&&value.value.length<=8388624,'RESOURCE_LIMIT');this.#bytes+=BigInt(value.value.length);ensure(this.#bytes<=116010000000n,'RESOURCE_LIMIT');this.#digest.update(value.value);return {done:false,ciphertext:value.value,archive_bytes:String(this.#bytes)};}
 close(){this.#closed=true;this.#transport.close();this.#reader?.cancel().catch(()=>{});if(this.#identity)this.#identity.identity='';this.#kit=undefined;}
}
