import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PortableReader,writePortable} from './portable.mjs';
import {parseTar,tarEntries,tarHeader,pageCommitment} from './archive.mjs';
import {decryptArchive,encryptArchive,independentExportIdentity,streamFromIterator} from '../../content-browser/age.mjs';
import {sceneForEvaluation} from '../complete-fixtures.mjs';
import {wire} from '../src/identity-codec.mjs';
import {pageCommitmentForEvaluation} from '../src/sync-reference.mjs';
import {sodium,hash} from '../adapters/primitives.mjs';
import {archiveHeader} from '../src/archive-profile.mjs';
const base=new URL('../../../fixtures/protocol/p02/v1/',import.meta.url),f=JSON.parse(readFileSync(new URL('crypto.json',base))).outputs,kit=f?.kit;
const actual=JSON.parse(readFileSync(new URL('crypto.json',base))).objects;
const archive=readFileSync(new URL('rust.age',base));
const source=bytes=>()=>new Blob([bytes]).stream();
async function collect(stream){const items=[];for await(const p of stream)items.push(p);return Buffer.concat(items);}
test('streaming USTAR bytes and inventory framing remain byte-identical to frozen P02',async()=>{
 for(const path of ['export-header.json','files/'+actual.file_export_key.revision_id+'/00000000.bin','identity/evidence.json'])assert.deepEqual(Buffer.from(tarHeader(path,17)),archiveHeader(path,17));
 const pages=[wire(actual.snapshot_page)];assert.deepEqual(pageCommitment('snapshot',pages),pageCommitmentForEvaluation('snapshot',pages));
});
test('maintained age reader verifies frozen complete archive independently, recovering note and file',async()=>{
 const reader=new PortableReader(source(archive),actual.kit);try{const result=await reader.validate();assert.equal(result.status,'VERIFIED_OFFLINE');assert.equal(result.live_destination_mutations,0);assert.equal((await reader.note(actual.payload.context.revision_id)).payload.title,actual.payload.title);let recovered=[];await reader.file(actual.file_export_key.revision_id,{write:bytes=>recovered.push(Buffer.from(bytes)),finish:()=>{},abort:()=>assert.fail('unexpected abort')});assert.equal(Buffer.concat(recovered).toString('hex'),actual.file_plain_hex);}finally{reader.close();}
});
test('new streaming export uses fresh independent identity and the same original cipherframes',async()=>{
 const entries=[];await parseTar(await decryptArchive(new Blob([archive]).stream(),actual.kit.export_identity),x=>{if(!x.path.startsWith('export-')&&!x.path.startsWith('inventory/'))entries.push({path:x.path,bytes:new Uint8Array(x.bytes)});});
 const signer=actual.footer.body.signer,key=sceneForEvaluation().owner.current.device.signing.privateKey;
 async function make(){const out=[];const result=await writePortable({header:actual.header,entries,signer,sign:bytes=>sodium.crypto_sign_detached(bytes,key),kit:{exporter_root_fingerprint:actual.kit.exporter_root_fingerprint,exporter_roster:actual.kit.exporter_roster,independent_group_pins:actual.kit.independent_group_pins},sink:{write:b=>out.push(Buffer.from(b)),finish:()=>{},abort:()=>assert.fail('unexpected abort')}});return {...result,archive:Buffer.concat(out)};}
 const a=await make(),b=await make();assert.notEqual(a.kit.export_identity,b.kit.export_identity);assert.notEqual(a.recipient,b.recipient);assert.equal(hash(a.archive),a.kit.archive_sha256);
 const reader=new PortableReader(source(a.archive),a.kit);await reader.validate();assert.equal((await reader.note(actual.payload.context.revision_id)).payload.title,actual.payload.title);reader.close();
});
test('wrong kit, outer truncation and tampering cannot expose provisional data',async()=>{
 const identity=await independentExportIdentity();for(const [bytes,k]of [[archive,{...actual.kit,export_identity:identity.identity}],[archive.subarray(0,-1),{...actual.kit,archive_sha256:hash(archive.subarray(0,-1))}],[Buffer.from(archive),actual.kit]]){if(bytes.length===archive.length&&k===actual.kit)bytes[bytes.length-100]^=1;const reader=new PortableReader(source(bytes),k);await assert.rejects(reader.validate());assert.throws(()=>reader.notes(),/EXPORT_NOT_VALIDATED/);reader.close();}
});
test('authenticated outer encryption cannot certify missing footer, trailing entry, unsafe tar or missing independent pin',async()=>{
 const inner=[];await parseTar(await decryptArchive(new Blob([archive]).stream(),actual.kit.export_identity),x=>inner.push({path:x.path,bytes:new Uint8Array(x.bytes)}));const independent=await independentExportIdentity();
 for(const changed of [inner.slice(0,-1),[...inner,{path:'identity/evidence.json',bytes:new Uint8Array([1])}]]){const bytes=await collect(await encryptArchive(streamFromIterator(tarEntries(changed)),independent.recipient));const reader=new PortableReader(source(bytes),{...actual.kit,export_identity:independent.identity,archive_sha256:hash(bytes)});await assert.rejects(reader.validate());}
 const noPin=new PortableReader(source(archive),{...actual.kit,independent_group_pins:[]});await assert.rejects(noPin.validate(),/INDEPENDENT_HISTORY_REQUIRED/);
 const header=tarHeader('export-header.json',0);header[156]=50;await assert.rejects(parseTar(streamFromIterator((async function*(){yield header;yield new Uint8Array(1024);})()),()=>{}),/INVALID_ARCHIVE_HEADER/);
});
