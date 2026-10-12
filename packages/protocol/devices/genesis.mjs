// Private settings genesis uses the frozen group-c2 policy/epoch/grant formats.
import {sodium,b64,un64,randomKey} from '../adapters/primitives.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {groupCodecForProfile} from '../adapters/codecs/group-codec.mjs';
import {certificateDetails,senderForCertificate,identityDetails,sealGroupKeyForEvaluation,verifyDistributionSignature} from './proofs.mjs';
import {rosterScope,rosterDetails,activeCertificateForEvaluation,activeRecipientForRosterEvaluation,recoveryRecipientForRosterEvaluation} from './roster.mjs';
import {ensure} from '../vault/store.mjs';
const g=groupCodecForProfile('p02-group-c2');
export function signGroup(kind,body,key){const raw=g.groupEncode(kind+'-body',wire(body));return g.groupDecode(kind,wire({body:JSON.parse(new TextDecoder().decode(raw)),...(kind==='policy'?{cosignature:null}:{}),signature:b64(sodium.crypto_sign_detached(g.groupSigningInput(kind+'-body',raw),key))}));}
export function verifyGroup(kind,record,key){const parsed=g.groupDecode(kind,wire(record));ensure(sodium.crypto_sign_verify_detached(un64(parsed.signature),g.groupSigningInput(kind+'-body',wire(parsed.body)),un64(key)),'INVALID_SIGNATURE');return parsed;}
export function recipients(roster,identity){return [...rosterDetails(roster).devices.filter(d=>d.status==='ACTIVE').map(d=>({recipient:activeRecipientForRosterEvaluation(roster,d.device_id),key:certificateDetails(activeCertificateForEvaluation(roster,d.device_id)).body.device_encryption_key})),{recipient:recoveryRecipientForRosterEvaluation(roster),key:identityDetails(identity).body.recovery_encryption_key}];}
export function privateGenesis(roster,identity,deviceId,privateKey){
 const group_id=b64(sodium.randombytes_buf(16)),operation_id=b64(sodium.randombytes_buf(16)),scope={service_id:rosterScope(roster).service_id,group_id},certificate=activeCertificateForEvaluation(roster,deviceId,'sign-content'),signer=senderForCertificate(certificate,rosterDetails(roster).head),key=randomKey();
 try{
  const policy=signGroup('policy',{...g.groupCommon('group-policy-event'),...scope,operation_id,action:'genesis',version:'0',predecessor:null,signer,members:[{account_id:signer.account_id,root_fingerprint:signer.root_fingerprint,role:'owner'}],payload:{group_kind:'private'}},privateKey);
  const membership={version:'0',digest:g.groupDigest('policy',wire(policy))};
  const intent=signGroup('epoch-intent',{...g.groupCommon('group-epoch-intent'),...scope,operation_id,reason:'genesis',expected_policy:membership,membership,previous_epoch:null,next_epoch:'0',retained_epochs:[],key_commitment:g.groupKeyCommitment(scope,key),rosters:[{account_id:signer.account_id,root_fingerprint:signer.root_fingerprint,recovery_generation:signer.recovery_generation,roster:signer.roster_head}],history_checkpoint_digest:null,signer,expires_at:String(Date.now()+600000)},privateKey);
  const epoch_digest=g.groupDigest('epoch-intent',wire(intent));
  const records=recipients(roster,identity).map(({recipient,key:recipientKey})=>JSON.parse(new TextDecoder().decode(sealGroupKeyForEvaluation(wire({purpose:'group-key-distribution',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,...scope,key_epoch:'0',epoch_digest,membership_head:membership,operation_id,issuer:signer,recipient}),key,un64(recipientKey),privateKey,certificate)))).sort((a,b)=>g.grantOrder(a)<g.grantOrder(b)?-1:g.grantOrder(a)>g.grantOrder(b)?1:0);
  const page=g.groupDecode('grant-page',wire({...g.groupCommon('group-grant-page'),...scope,operation_id,page_index:'0',records})),commitment=g.grantPageCommitment([wire(page)]);
  const descriptor=signGroup('descriptor',{...g.groupCommon('group-grant-descriptor'),...scope,operation_id,intent_digest:epoch_digest,membership,inventory_digest:commitment.digest,record_count:commitment.record_count,page_count:'1',epoch_inventory_digest:g.groupDigest('epochs',wire([{key_epoch:'0',epoch_digest,key_commitment:intent.body.key_commitment}])),signer},privateKey);
  const commit=signGroup('epoch-commit',{...g.groupCommon('group-epoch-commit'),...scope,operation_id,policy,intent,descriptor},privateKey);
  verifyGenesis({commit,pages:[page]},roster,identity);
  return {request:{version:1,commit,pages:[page]},secret:{service_id:scope.service_id,group_id,key_epoch:'0',epoch_digest,group_secret:b64(key)}};
 }finally{sodium.memzero(key);}
}
export function verifyGenesis({commit,pages},roster,identity){
 ensure(Array.isArray(pages)&&pages.length===1,'INVALID_REQUEST');const b=commit.body,p=b.policy?.body,i=b.intent.body,d=b.descriptor.body;
 ensure(p&&b.policy.cosignature===null&&p.action==='genesis'&&p.payload.group_kind==='private'&&p.version==='0'&&p.predecessor===null&&i.reason==='genesis'&&i.previous_epoch===null&&i.next_epoch==='0'&&i.retained_epochs.length===0,'INTEGRITY_FAILURE');
 const cert=activeCertificateForEvaluation(roster,b.intent.body.signer.device_id,'sign-content'),c=certificateDetails(cert),signer=senderForCertificate(cert,rosterDetails(roster).head),scope=rosterScope(roster);
 ensure(same(p.signer,signer)&&same(i.signer,signer)&&same(d.signer,signer)&&same(p.members,[{account_id:scope.account_id,root_fingerprint:scope.root_fingerprint,role:'owner'}]),'INTEGRITY_FAILURE');
 for(const [kind,r]of [['policy',b.policy],['epoch-intent',b.intent],['descriptor',b.descriptor],['epoch-commit',commit]]){verifyGroup(kind,r,c.body.device_signing_key);ensure(r.body.service_id===scope.service_id&&r.body.group_id===b.group_id&&r.body.operation_id===b.operation_id,'INTEGRITY_FAILURE');}
 const membership={version:'0',digest:g.groupDigest('policy',wire(b.policy))},epoch_digest=g.groupDigest('epoch-intent',wire(b.intent)),coverage=recipients(roster,identity),page=g.groupDecode('grant-page',wire(pages[0])),inventory=g.grantPageCommitment([wire(page)]);
 ensure(same(i.expected_policy,membership)&&same(i.membership,membership)&&same(d.membership,membership)&&d.intent_digest===epoch_digest&&d.inventory_digest===inventory.digest&&d.record_count===String(coverage.length)&&d.page_count==='1'&&d.epoch_inventory_digest===g.groupDigest('epochs',wire([{key_epoch:'0',epoch_digest,key_commitment:i.key_commitment}])),'INTEGRITY_FAILURE');
 ensure(same(i.rosters,[{account_id:scope.account_id,root_fingerprint:scope.root_fingerprint,recovery_generation:signer.recovery_generation,roster:signer.roster_head}])&&i.history_checkpoint_digest===null,'ROSTER_CHANGED');
 ensure(page.service_id===scope.service_id&&page.group_id===b.group_id&&page.operation_id===b.operation_id&&page.records.length===coverage.length,'INTEGRITY_FAILURE');
 const expected=new Map(coverage.map(x=>[x.recipient.kind+'/'+(x.recipient.device_id??''),x.recipient]));
 for(const r of page.records){const x=r.body.context,key=x.recipient.kind+'/'+(x.recipient.device_id??''),recipient=expected.get(key);ensure(recipient,'RECIPIENT_COVERAGE_MISMATCH');verifyDistributionSignature(wire(r),wire({purpose:'group-key-distribution',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,service_id:scope.service_id,group_id:b.group_id,key_epoch:'0',epoch_digest,membership_head:membership,operation_id:b.operation_id,issuer:signer,recipient}),cert);expected.delete(key);}
 ensure(expected.size===0,'RECIPIENT_COVERAGE_MISMATCH');return {group_id:b.group_id,epoch_digest,key_commitment:i.key_commitment,membership};
}
