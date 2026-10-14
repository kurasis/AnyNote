// Actual 1,000,000,000-byte portable file. Only ciphertext is staged on disk.
import assert from 'node:assert/strict';
import {readFileSync,createReadStream,createWriteStream,mkdirSync,rmSync,writeFileSync} from 'node:fs';
import {once} from 'node:events';
import {Readable} from 'node:stream';
import {spawn,execFileSync} from 'node:child_process';
import {rosterEvents,rosterDetails} from '../src/roster.mjs';
import {stateDecode} from '../src/state-codec.mjs';
import {verifyPortableEvidence} from './authority.mjs';
import {sceneForEvaluation,id} from '../complete-fixtures.mjs';
import {FileWriter} from '../adapters/files.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {common,encode} from '../adapters/codecs/protocol-codec.mjs';
import {envelopeDigest} from '../adapters/codecs/codec.mjs';
import {sodium,hash} from '../adapters/primitives.mjs';
import {createHash} from 'node:crypto';
import {pageCommitment} from './archive.mjs';
import {PortableReader,writePortable} from './portable.mjs';
const frozen=JSON.parse(readFileSync(new URL('../../../fixtures/protocol/p02/v1/crypto.json',import.meta.url))).objects;
const s=sceneForEvaluation(),version=id('p13-real-one-gigabyte'),context={...frozen.file_record.envelope.header.context,file_id:id('p13-large-file'),file_version_id:version,operation_id:id('p13-large-operation'),parents:[],policy:s.g.groupPolicyReference(s.group),author:s.author(1)},size=1000000000;
const directory='.local/p13-gigabyte-'+process.pid;mkdirSync(directory,{recursive:true,mode:0o700});let reader,maximumRss=process.memoryUsage().rss;const timer=setInterval(()=>maximumRss=Math.max(maximumRss,process.memoryUsage().rss),50),started=Date.now();
try{
 const writer=new FileWriter(wire(context),size),plainDigest=createHash('sha256');let count=0;const plain=new Uint8Array(8388608);for(let i=0;i<plain.length;i++)plain[i]=(i*37+11)%256;
 for(let offset=0;offset<size;offset+=plain.length){const part=plain.subarray(0,Math.min(plain.length,size-offset));plainDigest.update(part);const cipher=writer.encryptNext(part);writeFileSync(directory+'/'+String(count++).padStart(8,'0')+'.bin',cipher);cipher.fill(0);}plain.fill(0);
 const secrets=writer.checkpoint(),record=writer.finish('PUBLIC synthetic 1 GB.bin','application/octet-stream',s.keys.get(context.policy.key_epoch),s.accounts[1].current.device.signing.privateKey);const expectedDigest=plainDigest.digest('base64url');console.log('PASS: 1 GB original file encrypted into '+count+' bounded chunks');
 s.g.observeAcceptedFileForEvaluation(s.group,wire(record.envelope));const historyPage={purpose:'history-inventory-page',contract:'p02-file-c1',version:1,service_id:context.service_id,group_id:context.group_id,page_index:'0',records:s.g.observedHistoryRecordsForEvaluation(s.group)};
 const history=s.build.historyForEvaluation(s.group,s.sender(),s.owner.current.device.signing.privateKey,[wire(historyPage)]);s.g.endorseGroupHistoryForEvaluation(s.group,history,[wire(historyPage)],s.g.independentHistoryWitnessForEvaluation(s.group));const details=s.g.groupDetails(s.group);
 const evidence={accounts:s.accounts.map(a=>({identity:a.v.outputs.identity,pin:a.v.outputs.pin,events:rosterEvents(a.roster).map(e=>stateDecode('event',e))})),groups:[{genesis:s.codec.groupDecode('policy',s.genesis),genesis_pin:s.pin,transitions:s.transitions,history:s.codec.groupDecode('history',history),history_pages:[historyPage]}]};
 const snapshotPage={...frozen.snapshot_page,items:[{group_id:context.group_id,object_kind:'file-manifest',object_id:context.file_id,revision_id:version,envelope_digest:envelopeDigest(wire(record.envelope)),payload_status:'retained'}]};
 const snapshot={...frozen.header.snapshot,...pageCommitment('snapshot',[wire(snapshotPage)])},header={...frozen.header,snapshot,selection:{group_ids:[context.group_id],include_history:true,include_trash:true}};
 const key={...common('export-selected-key'),service_id:context.service_id,group_id:context.group_id,object_id:context.file_id,revision_id:version,key_kind:'manifest-and-file-deks',object_dek:secrets.manifest_key,file_data_dek:secrets.file_key};
 async function* entries(){for(let i=0;i<count;i++){const name=String(i).padStart(8,'0');yield {path:'files/'+version+'/'+name+'.bin',bytes:readFileSync(directory+'/'+name+'.bin')};}yield {path:'identity/evidence.json',bytes:encode('export-evidence',wire(evidence))};yield {path:'keys/'+version+'.json',bytes:encode('export-key',wire(key))};yield {path:'records/'+version+'.json',bytes:encode('export-file-record',wire(record))};yield {path:'snapshots/00000000.json',bytes:encode('snapshot-page',wire(snapshotPage))};}
 verifyPortableEvidence(encode('export-evidence',wire(evidence)),{exporter_root_fingerprint:header.root_fingerprint,exporter_roster:s.author(0).roster,independent_group_pins:[{group_id:context.group_id,genesis_digest:s.pin.genesis_digest,policy:details.policy,epoch:details.epoch,history:details.history}]});
 const output=createWriteStream(directory+'/archive.age',{flags:'wx',mode:0o600});const result=await writePortable({header,entries:entries(),signer:s.author(0),sign:bytes=>sodium.crypto_sign_detached(bytes,s.owner.current.device.signing.privateKey),kit:{exporter_root_fingerprint:header.root_fingerprint,exporter_roster:s.author(0).roster,independent_group_pins:[{group_id:context.group_id,genesis_digest:s.pin.genesis_digest,policy:details.policy,epoch:details.epoch,history:details.history}]},sink:{async write(bytes){if(!output.write(bytes))await once(output,'drain');},async finish(){output.end();await once(output,'close');},abort:()=>output.destroy()}});
 console.log('PASS: maintained age encrypted the streaming archive; no plaintext archive or key files');
 // Go age independently reads the JS stream. Identity travels through an inherited pipe.
 const child=spawn('bash',['-c','exec "$1" -d -i <(cat <&3) "$2"','anynote-age-interop','.local/p02-tools/age',directory+'/archive.age'],{stdio:['ignore','pipe','pipe','pipe']});child.stdio[3].end(result.kit.export_identity+'\n');child.stderr.resume();let goBytes=0;for await(const bytes of child.stdout)goBytes+=bytes.length;assert.equal(await new Promise(resolve=>child.on('close',resolve)),0);assert(goBytes>size);console.log('PASS: Go age independently authenticated the complete JS archive');
 reader=new PortableReader(()=>Readable.toWeb(createReadStream(directory+'/archive.age',{highWaterMark:65536})),result.kit);const validated=await reader.validate();assert.equal(validated.files.length,1);const recovered=createHash('sha256');let recoveredBytes=0;await reader.file(version,{write(bytes){recoveredBytes+=bytes.length;recovered.update(bytes);},finish(){},abort(){assert.fail('Unexpected abort');}});assert.equal(recoveredBytes,size);assert.equal(recovered.digest('base64url'),expectedDigest);console.log('PASS: clean offline authority, all chunk AEADs and 1 GB full plaintext digest');
 const report={status:'PASS',source_commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),source_tree_dirty:!!execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim(),plaintext_bytes:size,chunks:count,archive_bytes:result.archive_bytes,go_age_plain_tar_bytes:goBytes,maximum_observed_process_rss_bytes:maximumRss,elapsed_ms:Date.now()-started,plaintext_temporary_files:0,physical_acceptance:false};mkdirSync('artifacts/p13',{recursive:true});writeFileSync('artifacts/p13/gigabyte-development.json',JSON.stringify(report,null,2)+'\n');console.log(report);
}finally{clearInterval(timer);reader?.close();rmSync(directory,{recursive:true,force:true});}
