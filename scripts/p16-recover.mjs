// Offline recovery of independently witnessed private epoch-zero ciphertext.
// Rotated/shared/history recovery uses the complete maintained P13 portable reader.
import {readFileSync,openSync,writeSync,fsyncSync,closeSync,mkdtempSync,mkdirSync,renameSync,rmSync,existsSync,lstatSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {parseArgs} from 'node:util';
import {createHash} from 'node:crypto';
import {strictJson} from '../packages/protocol/src/strict-json.mjs';
import {recoverRoot} from '../packages/protocol/adapters/identity.mjs';
import {wire,same} from '../packages/protocol/adapters/codecs/identity-codec.mjs';
import {sodium,un64} from '../packages/protocol/adapters/primitives.mjs';
import {verifiedSnapshot,historicalSnapshot} from '../packages/protocol/devices/client.mjs';
import {verifyGenesis} from '../packages/protocol/devices/genesis.mjs';
import {activeCertificateForEvaluation} from '../packages/protocol/devices/roster.mjs';
import {certificateDetails,openGroupKeyForEvaluation,recipientForRecovery} from '../packages/protocol/devices/proofs.mjs';
import {groupCodec} from '../packages/protocol/shared/proof.mjs';
import {digest as noteDigest} from '../packages/protocol/adapters/codecs/protocol-codec.mjs';
import {openObject} from '../packages/protocol/adapters/core.mjs';
import {FileReader} from '../packages/protocol/adapters/files.mjs';
import {envelopeDigest} from '../packages/protocol/adapters/codecs/codec.mjs';
const ensure=(v,m)=>{if(!v)throw Error(m);};
const json=(p,max)=>{ensure(lstatSync(p).isFile()&&!lstatSync(p).isSymbolicLink()&&lstatSync(p).size<=max,'RESOURCE_LIMIT');return strictJson(readFileSync(p),max);};
export async function recover({catalogue,blobs,kit,checkpoint,output,confirm=false}){
 const source=json(catalogue,33554432),anchor=json(checkpoint,1048576),document=json(kit,262144);
 ensure(source.version===1&&source.purpose==='offline-private-genesis-recovery','UNSUPPORTED_RECOVERY_SOURCE');
 ensure(same(source.pins,anchor.pins)&&same(source.snapshot.head,anchor.roster),'ROLLBACK_QUARANTINE');
 verifiedSnapshot(source.snapshot,anchor.pins,anchor.roster);
 const p=source.genesis.commit.body.policy;
 ensure(p.body.payload.group_kind==='private'&&p.body.group_id===anchor.group_id&&groupCodec.groupDigest('policy',wire(p))===anchor.genesis_digest,'GENESIS_PIN_MISMATCH');
 const historical=historicalSnapshot(source.snapshot,anchor.pins,p.body.signer.roster_head),info=verifyGenesis(source.genesis,historical.roster,historical.identity);
 const grants=source.genesis.pages.flatMap(p=>p.records).filter(r=>r.body.context.recipient.kind==='account-recovery');
 ensure(grants.length===1,'KEYS_PENDING');
 const grant=grants[0],ctx=grant.body.context,issuer=historicalSnapshot(source.snapshot,anchor.pins,ctx.issuer.roster_head),cert=activeCertificateForEvaluation(issuer.roster,ctx.issuer.device_id,'distribute-group-key');
 ensure(ctx.service_id===anchor.pins.service_id&&ctx.group_id===anchor.group_id&&ctx.epoch_digest===info.epoch_digest&&same(ctx.recipient,recipientForRecovery(issuer.identity,issuer.details.generation,issuer.details.head)),'GRANT_CONTEXT_MISMATCH');
 const root=await recoverRoot(wire(document.kit??document),wire(anchor.pins));let key,temporary;
 try{
  key=openGroupKeyForEvaluation(wire(grant),wire(ctx),cert,root.recovery.publicKey,root.recovery.privateKey);
  ensure(groupCodec.groupKeyCommitment({service_id:anchor.pins.service_id,group_id:anchor.group_id},key)===info.key_commitment,'INTEGRITY_FAILURE');
  const selected=new Map(anchor.records.map(r=>[r.revision_id,r.envelope_digest]));
  ensure(selected.size===anchor.records.length&&source.records.length+source.files.length<=1032,'RESOURCE_LIMIT');
  const witnessed=(record,file=false)=>{const e=record.envelope,c=e.header.context,id=file?c.file_version_id:c.revision_id;ensure(c.service_id===anchor.pins.service_id&&c.group_id===anchor.group_id&&c.policy.key_epoch==='0'&&selected.get(id)===(file?envelopeDigest(wire(e)):noteDigest('envelope',wire(e))),'UNWITNESSED_RECOVERY_RECORD');const a=historicalSnapshot(source.snapshot,anchor.pins,c.author.roster),certificate=activeCertificateForEvaluation(a.roster,c.author.device_id,'sign-content');ensure(c.author.account_id===anchor.pins.account_id&&c.author.root_fingerprint===anchor.pins.root_fingerprint&&c.author.recovery_generation===certificateDetails(certificate).body.recovery_generation,'CONTEXT_MISMATCH');return {id,c,publicKey:un64(certificateDetails(certificate).body.device_signing_key)};};
  const result={status:'VERIFIED_OFFLINE',network_used:false,server_authorization_restored:false,notes:[],files:[]};
  const paths=new Set();
  const visit=async(write=false)=>{
   for(const record of source.records){const w=witnessed(record),payload=openObject(wire(record),key,w.publicKey,wire(w.c));if(write){const fd=openSync(join(temporary,'note-'+w.id+'.json'),'wx',0o600);try{writeSync(fd,JSON.stringify(payload));fsyncSync(fd);}finally{closeSync(fd);}}else{ensure(!paths.has(w.id),'DUPLICATE_RECORD');paths.add(w.id);result.notes.push({revision_id:w.id});}}
   for(const file of source.files){const w=witnessed(file.record,true),reader=new FileReader(wire(file.record),key,w.publicKey,wire(w.c)),hash=createHash('sha256');let bytes=0,fd;
    try{if(write)fd=openSync(join(temporary,'file-'+w.id+'.bin'),'wx',0o600);for(const part of file.chunks){ensure(/^[A-Za-z0-9_-]{22}$/.test(part.blob_id),'UNSAFE_BLOB_PATH');const path=resolve(blobs,part.blob_id),stat=lstatSync(path);ensure(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=8388624,'RESOURCE_LIMIT');const cipher=readFileSync(path);ensure(String(cipher.length)===String(part.ciphertext_bytes)&&createHash('sha256').update(cipher).digest('base64url')===part.digest,'CHUNK_DIGEST_MISMATCH');const plain=reader.decryptNext(cipher);try{bytes+=plain.length;hash.update(plain);if(write)writeSync(fd,plain);}finally{plain.fill(0);}}reader.finish();if(write)fsyncSync(fd);else{ensure(!paths.has(w.id),'DUPLICATE_RECORD');paths.add(w.id);result.files.push({file_version_id:w.id,plaintext_bytes:bytes,sha256:hash.digest('hex')});}}
    finally{reader.close();if(fd!==undefined)closeSync(fd);}
   }
  };
  await visit();ensure(paths.size===selected.size,'INCOMPLETE_RECOVERY_SOURCE');
  if(output){ensure(confirm&&!existsSync(output),'EXPLICIT_NEW_PLAINTEXT_DESTINATION_REQUIRED');temporary=mkdtempSync(join(dirname(resolve(output)),'.anynote-p16-recovery-'));await visit(true);const fd=openSync(temporary,'r');try{fsyncSync(fd);}finally{closeSync(fd);}renameSync(temporary,output);temporary=undefined;result.plaintext_output=true;}
  return result;
 }finally{if(temporary)rmSync(temporary,{recursive:true,force:true});if(key)sodium.memzero(key);sodium.memzero(root.signing.privateKey);sodium.memzero(root.recovery.privateKey);}
}
if(process.argv[1]===new URL(import.meta.url).pathname){
 const {values:v}=parseArgs({options:{catalogue:{type:'string'},blobs:{type:'string'},kit:{type:'string'},checkpoint:{type:'string'},output:{type:'string'},'plaintext-confirm':{type:'boolean'}}});
 try{console.log(JSON.stringify(await recover({...v,confirm:v['plaintext-confirm']})));}catch(e){console.error('Offline recovery refused:',e.message);process.exitCode=1;}
}
