// Actual independent native process verifies every signed roster event beyond the old limit.
import {fixture,run,sync} from '../../packages/protocol/notes/test-fixture.mjs';
import {nativeHarness} from '../../packages/protocol/devices/native-harness.mjs';
import {rootEventForEvaluation} from '../../packages/protocol/devices/enrollment.mjs';
import {verifiedSnapshot} from '../../packages/protocol/devices/client.mjs';
import {applyRosterEventForEvaluation,rosterDetails} from '../../packages/protocol/devices/roster.mjs';
import {sodium,b64,hash,deviceKeys} from '../../packages/protocol/adapters/primitives.mjs';
import {wire} from '../../packages/protocol/adapters/codecs/identity-codec.mjs';
import {stateDigest} from '../../packages/protocol/adapters/codecs/state-codec.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const id=()=>b64(sodium.randombytes_buf(16)),f=await fixture(),proof=verifiedSnapshot(f.snapshot,f.pins),events=structuredClone(f.snapshot.events);let native,checks=0;
const check=v=>{if(!v)throw Error('P11_NATIVE_ROSTER_CHECK');checks++;};
try{
 for(let n=0;n<1000;n++){
  const keys=deviceKeys();try{
   const before=rosterDetails(proof.roster),device={device_id:id(),signing_key:b64(keys.signing.publicKey),encryption_key:b64(keys.encryption.publicKey),capabilities:['delegate-device','distribute-group-key','receive-group-key','sign-content']},context={purpose:'device-possession-challenge',contract:'p02-state-c1',protocol:'anynote',protocol_version:1,...f.pins,intent:'reset',challenge_id:id(),session_binding:hash(sodium.randombytes_buf(32)),generation:before.generation,roster:before.head,nonce:b64(sodium.randombytes_buf(32)),device,expires_at:String(Date.now()+50000)},plain={purpose:'device-encryption-proof',context,secret:b64(sodium.randombytes_buf(32))},challenge={context,sealed_challenge:b64(sodium.crypto_box_seal(wire(plain),keys.encryption.publicKey)),challenge_digest:stateDigest('challenge-plaintext',wire(plain))},event=JSON.parse(new TextDecoder().decode(rootEventForEvaluation(proof.roster,wire(challenge),keys,f.initial.root.signing.privateKey)));
   applyRosterEventForEvaluation(proof.roster,wire(event));events.push(event);
  }finally{sodium.memzero(keys.signing.privateKey);sodium.memzero(keys.encryption.privateKey);}
 }
 const d=rosterDetails(proof.roster),snapshot={identity:f.snapshot.identity,head:d.head,generation:d.generation,events};check(events.length===1001);check(verifiedSnapshot(snapshot,f.pins,f.snapshot.head).details.head.digest===d.head.digest);
 await sync(f.old,snapshot);check((await run(f.old,'summary')).state==='REVOKED');
 native=await nativeHarness({scope:{service_id:f.pins.service_id,account_id:f.pins.account_id,device_id:id(),profile_id:id()},pins:f.pins,phrase:'public synthetic purple harbor paper lantern'});check(!native.device.error);
 const stored=await native.call({operation:'device-snapshot',snapshot});if(stored.error)throw Error('P11_NATIVE_SNAPSHOT_'+stored.error);check(!stored.error);check(stored.head.digest===d.head.digest);
 const shortened=structuredClone(snapshot);shortened.events.splice(700,1);check(!!(await native.call({operation:'device-snapshot',snapshot:shortened})).error);
 const corrupt=structuredClone(snapshot);corrupt.events[900].signature=b64(sodium.randombytes_buf(64));check(!!(await native.call({operation:'device-snapshot',snapshot:corrupt})).error);
 check(!!(await native.call({operation:'device-snapshot',snapshot:f.snapshot})).error);
 const git=(...args)=>execFileSync('git',args,{encoding:'utf8'}).trim(),report={purpose:'P11 actual native/portable signed history beyond 1000 events',status:'PASS',checks,events:events.length,source_commit:git('rev-parse','HEAD'),source_tree:git('rev-parse','HEAD^{tree}'),source_tree_dirty:git('status','--porcelain')!=='',physical_acceptance:false,independent_review:'NOT_RUN'};mkdirSync('artifacts/p11',{recursive:true});writeFileSync('artifacts/p11/native-interop-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{await native?.close();f.initial.dispose();await f.old.engine.close();await f.fresh.engine.close();sodium.memzero(f.keys.signing.privateKey);sodium.memzero(f.keys.encryption.privateKey);}
