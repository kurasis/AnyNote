// Dedicated-worker state machine. Hooks store only encrypted public evidence and vault secrets under L.
import {canonicalBytes} from '../adapters/core.mjs';
import {sodium,b64,un64,hash,Buffer} from '../adapters/primitives.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {stateDecode,stateDigest} from '../adapters/codecs/state-codec.mjs';
import {groupCodecForProfile} from '../adapters/codecs/group-codec.mjs';
import {recoverRoot} from '../adapters/identity.mjs';
import {verifiedSnapshot,historicalSnapshot} from './client.mjs';
import {verifyRootIdentity,certificateDetails,identityDetails,verifyDistributionSignature,openGroupKeyForEvaluation,sealGroupKeyForEvaluation,senderForCertificate} from './proofs.mjs';
import {newRosterForEvaluation,applyRosterEventForEvaluation,rosterDetails,rosterScope,activeCertificateForEvaluation,activeRecipientForRosterEvaluation,recoveryRecipientForRosterEvaluation,verifyStateRecord,verifyPairingTranscript,verifyEnrollmentApproval,revokedDescendants} from './roster.mjs';
import {invitationForEvaluation,offerForEvaluation,responseForEvaluation,approvalForEvaluation,confirmationForEvaluation,enrollmentEventForEvaluation,revokeEventForEvaluation,rootEventForEvaluation,randomOperationId} from './enrollment.mjs';
import {pairingQr,scannedChannelForEvaluation,generatePairingKey,sealPairingFrame,openPairingFrame,closePairingChannel} from './pairing-channel.mjs';
import {privateGenesis,verifyGenesis} from './genesis.mjs';
import {ensure,id} from '../vault/store.mjs';
const parse=bytes=>JSON.parse(new TextDecoder().decode(bytes)),g=groupCodecForProfile('p02-group-c2');
export const controlId=scope=>b64(un64(hash(Buffer.concat([Buffer.from('AnyNote/P08/local-control\0'),canonicalBytes(wire(scope))]))).subarray(0,16));
export class DeviceWorkflow {
 #keys;#channel;#stage;#proof;#snapshot;#state;
 constructor({scope,pins,keys,load,persist,anchor=null}){this.scope=scope;this.pins=pins;this.#keys=keys;this.load=load;this.persist=persist;this.anchor=anchor;}
 async #ready(){if(this.#state)return;const saved=await this.load(false);this.#state=saved.control??{purpose:'p08-installation-control',version:1,identity:null,head:null,generation:null,pages:[],staging:null,pending:null,kit_verified:false};ensure(this.#state.purpose==='p08-installation-control'&&this.#state.version===1&&Array.isArray(this.#state.pages),'INTEGRITY_FAILURE');if(this.#state.head){const events=[];for(const page of saved.pages)events.push(...page);this.#snapshot={identity:this.#state.identity,events,head:this.#state.head,generation:this.#state.generation};this.#proof=verifiedSnapshot(this.#snapshot,this.pins,this.anchor);}}
 #device(){return {device_id:this.scope.device_id,signing_key:b64(this.#keys.signing.publicKey),encryption_key:b64(this.#keys.encryption.publicKey),capabilities:['delegate-device','distribute-group-key','receive-group-key','sign-content']};}
 #active(capability){ensure(this.#proof,'ROSTER_PROOF_REQUIRED');const cert=activeCertificateForEvaluation(this.#proof.roster,this.scope.device_id,capability),b=certificateDetails(cert).body;ensure(b.device_signing_key===b64(this.#keys.signing.publicKey)&&b.device_encryption_key===b64(this.#keys.encryption.publicKey),'DEVICE_KEY_MISMATCH');return cert;}
 #binding(session){ensure(id(session),'INVALID_SESSION');return hash(Buffer.from('AnyNote/P06/session-binding\0'+session));}
 #ceremony(){const p=this.#state.pending;ensure(p,'PAIRING_REQUIRED');return {service_id:this.pins.service_id,account_id:this.pins.account_id,root_fingerprint:this.pins.root_fingerprint,device:p.offer?.body.device??null,device_fingerprint:p.offer?hash(Buffer.concat([Buffer.from('AnyNote/P08/device-preview\0'),canonicalBytes(wire(p.offer.body.device))])):null,operation_id:p.operation_id,expires_at:p.expires_at,origin_required:true};}
 #live(){ensure(this.#channel&&this.#state.pending,'PAIRING_RESTART_REQUIRED');ensure(BigInt(this.#state.pending.expires_at)>BigInt(Date.now()),'ENROLLMENT_EXPIRED');}
 async #commit(extra={}){await this.persist(this.#state,extra);}
 close(){if(this.#channel){try{closePairingChannel(this.#channel);}catch{}}this.#channel=undefined;this.#stage=undefined;this.#proof=undefined;this.#snapshot=undefined;this.#state=undefined;}
 async command(op,args=[]){
  await this.#ready();
  ensure(!this.#stage||['snapshotStart','snapshotPage','snapshotFinish','summary'].includes(op),'SNAPSHOT_PENDING');
  if(op==='snapshotStart'){
   const [identityInput,headInput,generation]=args,identity=structuredClone(identityInput),head=structuredClone(headInput);stateDecode('head',wire(head));ensure(typeof generation==='string','INVALID_REQUEST');const proof=verifyRootIdentity(wire(identity),wire(this.pins));
   this.#stage={identity,head,generation,roster:newRosterForEvaluation(proof),identityProof:proof,events:[],bytes:0,observed:this.#state.head===null};
   const abandoned=this.#state.staging?.pages??[];this.#state.staging={pages:[]};await this.#commit({deletePages:abandoned});return {state:'snapshot-pending'};
  }
  if(op==='snapshotPage'){
   ensure(this.#stage,'SNAPSHOT_REQUIRED');const [events]=args;ensure(Array.isArray(events)&&events.length>0&&events.length<=20&&wire(events).length<=262144,'RESOURCE_LIMIT');
   const stage=this.#stage;stage.bytes+=wire(events).length;ensure(stage.bytes<=33554432&&stage.events.length+events.length<=10000,'RESOURCE_LIMIT');
   for(const event of events){applyRosterEventForEvaluation(stage.roster,wire(event));stage.events.push(structuredClone(event));if(this.#state.head&&same(rosterDetails(stage.roster).head,this.#state.head))stage.observed=true;}
   const pageId=randomOperationId();this.#state.staging.pages.push(pageId);await this.#commit({page:{id:pageId,events}});return {state:'snapshot-page-saved',records:events.length};
  }
  if(op==='snapshotFinish'){
   const stage=this.#stage;ensure(stage&&stage.observed,'ROLLBACK_QUARANTINE');const details=rosterDetails(stage.roster);ensure(same(details.head,stage.head)&&details.generation===stage.generation&&stage.events.length===Number(stage.head.version)+1,'INTEGRITY_FAILURE');
   const old=this.#state.pages;this.#state.identity=stage.identity;this.#state.head=stage.head;this.#state.generation=stage.generation;this.#state.pages=this.#state.staging.pages;this.#state.staging=null;
   await this.#commit({deletePages:old});this.#proof={identity:stage.identityProof,roster:stage.roster,details};this.#snapshot={identity:stage.identity,head:stage.head,generation:stage.generation,events:stage.events};this.#stage=undefined;return this.command('summary');
  }
  if(op==='retryRegistration'){ensure(this.#state.registration_request,'REGISTRATION_REQUIRED');return {request:this.#state.registration_request};}
  if(op==='finishRegistration'){this.#active('sign-content');ensure(this.#state.registration_request&&this.#snapshot.events.some(e=>e.body.operation_id===this.#state.registration_request.operation_id),'ROSTER_CHANGED');delete this.#state.registration_request;await this.#commit();return {state:'registration-completed'};}
  if(op==='publicDevice')return {device:this.#device()};
  if(op==='summary')return {state:this.#proof?.details.devices.find(d=>d.device_id===this.scope.device_id)?.status??'PENDING',head:this.#state.head,generation:this.#state.generation,active_device_limit:this.#proof?.details.active_device_limit??null,devices:this.#proof?.details.devices??[],kit_verified:this.#state.kit_verified,pending:this.#state.pending?{operation_id:this.#state.pending.operation_id,state:this.#state.pending.event?'confirmation-retry':this.#channel?'in-progress':'restart-required',expires_at:this.#state.pending.expires_at}:null};
  if(op==='startInvite'||op==='startOffer'){
   ensure(!this.#state.pending,'PAIRING_BUSY');ensure(this.#proof,'ROSTER_PROOF_REQUIRED');const operation_id=randomOperationId(),expires_at=String(Date.now()+540000),mode=op==='startInvite'?'existing-device-invitation':'new-device-offer';let record;
   if(op==='startInvite'){this.#active('delegate-device');record=invitationForEvaluation(this.#proof.roster,this.scope.device_id,operation_id,expires_at,this.#keys.signing.privateKey);}
   else{ensure(!this.#proof.details.devices.some(d=>d.device_id===this.scope.device_id),'DEVICE_ALREADY_REGISTERED');record=offerForEvaluation(this.#proof.roster,wire(this.#device()),this.#binding(args[0]),operation_id,expires_at,this.#keys.signing.privateKey);}
   const key=generatePairingKey();try{const qr=pairingQr(mode,record,key);this.#channel=scannedChannelForEvaluation(qr,op==='startInvite'?'approver':'new-device');this.#state.pending={operation_id,expires_at,mode,invitation:op==='startInvite'?parse(record):null,offer:op==='startOffer'?parse(record):null,response:null,approval:null,event:null};await this.#commit();return {qr:new TextDecoder().decode(qr),request:{version:1,mode,record:parse(record)},ceremony:this.#ceremony()};}finally{sodium.memzero(key);}
  }
  if(op==='scan'){
   ensure(!this.#state.pending&&this.#proof,'PAIRING_BUSY');const [qrText,session]=args;ensure(typeof qrText==='string','INVALID_REQUEST');const qr=stateDecode('qr',Buffer.from(qrText)),record=qr.record.body,details=rosterDetails(this.#proof.roster);
   for(const field of ['service_id','account_id','root_fingerprint'])ensure(record[field]===this.pins[field],'ROOT_PIN_MISMATCH');ensure(record.generation===details.generation&&same(record.roster,details.head),'ROSTER_CHANGED');ensure(BigInt(record.expires_at)>BigInt(Date.now())&&BigInt(record.expires_at)<=BigInt(Date.now()+600000),'ENROLLMENT_EXPIRED');
   this.#state.pending={operation_id:record.operation_id,expires_at:record.expires_at,mode:qr.mode,invitation:null,offer:null,response:null,approval:null,event:null};
   if(qr.mode==='new-device-offer'){
    this.#active('delegate-device');this.#channel=scannedChannelForEvaluation(Buffer.from(qrText),'approver');this.#state.pending.offer=qr.record;
    const response=responseForEvaluation(this.#proof.roster,wire(qr.record),this.scope.device_id,this.#keys.signing.privateKey,null,BigInt(Date.now()));this.#state.pending.response=parse(response.response);
    const frame=sealPairingFrame(this.#channel,'approver-response',response.response,stateDigest('offer',wire(qr.record)));await this.#commit();return {request:{version:1,frame:parse(frame),offer:null},ceremony:this.#ceremony()};
   }
   ensure(!details.devices.some(d=>d.device_id===this.scope.device_id),'DEVICE_ALREADY_REGISTERED');const cert=activeCertificateForEvaluation(this.#proof.roster,record.approver.device_id,'delegate-device');ensure(certificateDetails(cert).digest===record.approver.certificate_digest,'INVALID_SIGNATURE');verifyStateRecord('invitation',qr.record,certificateDetails(cert).body.device_signing_key);
   this.#channel=scannedChannelForEvaluation(Buffer.from(qrText),'new-device');this.#state.pending.invitation=qr.record;
   const offer=offerForEvaluation(this.#proof.roster,wire(this.#device()),this.#binding(session),record.operation_id,record.expires_at,this.#keys.signing.privateKey,wire(qr.record));this.#state.pending.offer=parse(offer);
   const frame=sealPairingFrame(this.#channel,'new-device-offer',offer,stateDigest('invitation',wire(qr.record)));await this.#commit();return {request:{version:1,frame:parse(frame),offer:parse(offer)},ceremony:this.#ceremony()};
  }
  if(op==='receive'){
   this.#live();const [frame]=args,p=this.#state.pending,message=frame.context.message;let bytes;
   if(message==='new-device-offer'){
    ensure(p.invitation&&!p.offer,'PAIRING_ORDER');bytes=openPairingFrame(this.#channel,wire(frame),message,stateDigest('invitation',wire(p.invitation)));p.offer=parse(bytes);
    const response=responseForEvaluation(this.#proof.roster,bytes,this.scope.device_id,this.#keys.signing.privateKey,wire(p.invitation),BigInt(Date.now()));p.response=parse(response.response);
    const responseFrame=sealPairingFrame(this.#channel,'approver-response',response.response,stateDigest('offer',bytes));await this.#commit();return {request:{version:1,frame:parse(responseFrame),offer:null},ceremony:this.#ceremony()};
   }
   if(message==='approver-response'){
    ensure(p.offer&&!p.response,'PAIRING_ORDER');bytes=openPairingFrame(this.#channel,wire(frame),message,stateDigest('offer',wire(p.offer)));p.response=parse(bytes);verifyPairingTranscript(this.#proof.roster,wire(this.#transcript()),BigInt(Date.now()));await this.#commit();return {state:'response-verified',ceremony:this.#ceremony()};
   }
   if(message==='approver-approval'){
    ensure(p.response&&!p.approval,'PAIRING_ORDER');bytes=openPairingFrame(this.#channel,wire(frame),message,stateDigest('transcript',wire(this.#transcript())));p.approval=parse(bytes);verifyEnrollmentApproval(this.#proof.roster,wire(this.#transcript()),bytes,BigInt(Date.now()));await this.#commit();return {state:'confirmation-required',ceremony:this.#ceremony()};
   }
   throw Error('PAIRING_ORDER');
  }
  if(op==='approve'){
   this.#live();this.#active('delegate-device');ensure(args.length===1&&args[0]===true,'USER_CONFIRMATION_REQUIRED');const p=this.#state.pending,t=this.#transcript();ensure(p.response&&!p.approval,'PAIRING_ORDER');
   const approval=approvalForEvaluation(this.#proof.roster,wire(t),this.#keys.signing.privateKey,BigInt(Date.now()));p.approval=parse(approval);const frame=sealPairingFrame(this.#channel,'approver-approval',approval,stateDigest('transcript',wire(t)));await this.#commit();return {request:{version:1,transcript:t,approval:p.approval,frame:parse(frame)},ceremony:this.#ceremony()};
  }
  if(op==='confirm'){
   this.#live();ensure(args.length===1&&args[0]===true,'USER_CONFIRMATION_REQUIRED');const p=this.#state.pending;ensure(p.approval&&!p.event,'PAIRING_ORDER');const t=wire(this.#transcript()),a=wire(p.approval),confirmation=confirmationForEvaluation(this.#proof.roster,t,a,this.#keys.encryption.privateKey,this.#keys.signing.privateKey,BigInt(Date.now())),event=enrollmentEventForEvaluation(this.#proof.roster,t,a,confirmation,this.#keys.signing.privateKey);p.event=parse(event);await this.#commit();return {request:{version:1,event:p.event}};
  }
  if(op==='retryConfirmation'){ensure(this.#state.pending?.event,'CONFIRMATION_REQUIRED');return {request:{version:1,event:this.#state.pending.event}};}
  if(op==='finishPairing'){ensure(this.#state.pending,'PAIRING_REQUIRED');const p=this.#state.pending;ensure(this.#snapshot?.events.some(e=>e.body.operation_id===p.operation_id&&['enroll','reset'].includes(e.body.kind)),'ROSTER_CHANGED');if(this.#channel)closePairingChannel(this.#channel);this.#channel=undefined;this.#state.pending=null;await this.#commit();return this.command('summary');}
  if(op==='cancel'){if(this.#channel)closePairingChannel(this.#channel);this.#channel=undefined;const operation_id=this.#state.pending?.operation_id;this.#state.pending=null;await this.#commit();return {operation_id:operation_id??null,state:'cancelled',fresh_device_keys_required:true};}
  if(op==='revoke'){
   this.#active('delegate-device');const [targets,confirmed]=args;ensure(confirmed===true,'USER_CONFIRMATION_REQUIRED');ensure(Array.isArray(targets)&&targets.length>0,'INVALID_REQUEST');const affected=revokedDescendants(this.#proof.roster,[...targets].sort());ensure(!affected.includes(this.scope.device_id),'REVOKER_IN_CLOSURE');this.#state.revoke_request={version:1,event:parse(revokeEventForEvaluation(this.#proof.roster,this.scope.device_id,targets,this.#keys.signing.privateKey))};await this.#commit();return {request:this.#state.revoke_request,affected};
  }
  if(op==='retryRevoke'){ensure(this.#state.revoke_request,'REVOKE_REQUIRED');return {request:this.#state.revoke_request};}
  if(op==='genesis'){
   this.#active('sign-content');if(this.#state.genesis_request)return {request:this.#state.genesis_request};const result=privateGenesis(this.#proof.roster,this.#proof.identity,this.scope.device_id,this.#keys.signing.privateKey);this.#state.genesis_request=result.request;await this.#commit({addKeys:[result.secret]});result.secret.group_secret='';return {request:result.request};
  }
  if(op==='verifyKit'){
   const [kit,accountSuffix,secretSuffix]=args;ensure(kit.account_id===this.pins.account_id&&kit.service_id===this.pins.service_id&&kit.root_fingerprint===this.pins.root_fingerprint&&accountSuffix===kit.account_id.slice(-6)&&secretSuffix===kit.recovery_secret.slice(-6),'KIT_VERIFICATION_REQUIRED');const root=await recoverRoot(wire(kit),wire(this.pins));try{this.#state.kit_verified=true;await this.#commit();return {state:'recovery-kit-verified'};}finally{sodium.memzero(root.signing.privateKey);sodium.memzero(root.recovery.privateKey);kit.recovery_secret='';}
  }
  if(op==='reset'){
   const [kit,challenge,session,confirmed]=args;ensure(confirmed===true&&this.#proof&&challenge.context.intent==='reset'&&challenge.context.session_binding===this.#binding(session)&&challenge.context.device.device_id===this.scope.device_id,'CHALLENGE_CONTEXT_MISMATCH');
   for(const f of ['service_id','account_id','root_fingerprint'])ensure(challenge.context[f]===this.pins[f],'ROOT_PIN_MISMATCH');ensure(challenge.context.device.signing_key===b64(this.#keys.signing.publicKey)&&challenge.context.device.encryption_key===b64(this.#keys.encryption.publicKey)&&challenge.context.generation===this.#proof.details.generation&&same(challenge.context.roster,this.#proof.details.head),'ROSTER_CHANGED');
   const root=await recoverRoot(wire(kit),wire(this.pins));try{const event=parse(rootEventForEvaluation(this.#proof.roster,wire(challenge),this.#keys,root.signing.privateKey,this.#proof.details.active_device_limit));this.#state.pending={operation_id:event.body.operation_id,expires_at:challenge.context.expires_at,mode:'recovery',event};await this.#commit();return {request:{version:1,event}};}finally{sodium.memzero(root.signing.privateKey);sodium.memzero(root.recovery.privateKey);kit.recovery_secret='';}
  }
  if(op==='recoverKeys'||op==='distribute'){
   this.#active('distribute-group-key');const [evidence,recordsOrTarget,kit,confirmed]=args;ensure(confirmed===true,'USER_CONFIRMATION_REQUIRED');const history=historicalSnapshot(this.#snapshot,this.pins,evidence.commit.body.policy.body.signer.roster_head),info=verifyGenesis(evidence,history.roster,history.identity);ensure(evidence.commit.body.policy.body.members[0].account_id===this.scope.account_id,'POLICY_REQUIRED');
   const sender=senderForCertificate(this.#active('distribute-group-key'),this.#proof.details.head),keys=await this.load(true);let groupKey,root;
   try{
    if(op==='recoverKeys'){
     ensure(Array.isArray(recordsOrTarget)&&recordsOrTarget.length>0&&recordsOrTarget.length<=60,'RESOURCE_LIMIT');root=await recoverRoot(wire(kit),wire(this.pins));const matches=recordsOrTarget.filter(r=>r.body.context.group_id===info.group_id&&r.body.context.key_epoch==='0'&&r.body.context.recipient.kind==='account-recovery');ensure(matches.length===1,'KEYS_PENDING');const record=matches[0],ctx=record.body.context,issuer=historicalSnapshot(this.#snapshot,this.pins,ctx.issuer.roster_head),cert=activeCertificateForEvaluation(issuer.roster,ctx.issuer.device_id,'distribute-group-key');ensure(ctx.service_id===this.pins.service_id&&ctx.recipient.account_id===this.pins.account_id&&ctx.recipient.root_fingerprint===this.pins.root_fingerprint&&same(ctx.recipient,recoveryRecipientForRosterEvaluation(issuer.roster))&&ctx.epoch_digest===info.epoch_digest&&same(ctx.membership_head,info.membership)&&same(ctx.issuer,senderForCertificate(cert,issuer.details.head)),'GRANT_CONTEXT_MISMATCH');groupKey=openGroupKeyForEvaluation(wire(record),wire(ctx),cert,root.recovery.publicKey,root.recovery.privateKey);
    }else{const stored=keys.secrets.group_keys.find(k=>k.group_id===info.group_id&&k.key_epoch==='0'&&k.epoch_digest===info.epoch_digest);ensure(stored,'KEYS_PENDING');groupKey=un64(stored.group_secret);}
    ensure(g.groupKeyCommitment({service_id:this.pins.service_id,group_id:info.group_id},groupKey)===info.key_commitment,'INTEGRITY_FAILURE');const target=op==='recoverKeys'?this.scope.device_id:recordsOrTarget,recipient=activeRecipientForRosterEvaluation(this.#proof.roster,target),cert=activeCertificateForEvaluation(this.#proof.roster,target,'receive-group-key'),publicKey=certificateDetails(cert).body.device_encryption_key;
    const context={purpose:'group-key-distribution',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,service_id:this.pins.service_id,group_id:info.group_id,key_epoch:'0',epoch_digest:info.epoch_digest,membership_head:info.membership,operation_id:randomOperationId(),issuer:sender,recipient};const grant=parse(sealGroupKeyForEvaluation(wire(context),groupKey,un64(publicKey),this.#keys.signing.privateKey,this.#active('distribute-group-key')));
    const request={version:1,records:[grant]};this.#state.grant_request=request;await this.#commit(op==='recoverKeys'?{addKeys:[{service_id:this.pins.service_id,group_id:info.group_id,key_epoch:'0',epoch_digest:info.epoch_digest,group_secret:b64(groupKey)}]}:{});return {request,group_id:info.group_id,state:'keys-local-saved'};
   }finally{if(groupKey)sodium.memzero(groupKey);if(root){sodium.memzero(root.signing.privateKey);sodium.memzero(root.recovery.privateKey);}if(kit)kit.recovery_secret='';if(keys.secrets){keys.secrets.device_signing_secret='';keys.secrets.device_encryption_secret='';for(const k of keys.secrets.group_keys)k.group_secret='';}}
  }
  if(op==='retryGrant'){ensure(this.#state.grant_request,'KEYS_PENDING');return {request:this.#state.grant_request};}
  if(op==='acceptKeys'){
   this.#active('receive-group-key');const [evidence,records]=args,history=historicalSnapshot(this.#snapshot,this.pins,evidence.commit.body.policy.body.signer.roster_head),info=verifyGenesis(evidence,history.roster,history.identity);ensure(Array.isArray(records)&&records.length<=60,'RESOURCE_LIMIT');const matches=records.filter(r=>r.body.context.group_id===info.group_id&&r.body.context.recipient.device_id===this.scope.device_id&&r.body.context.key_epoch==='0');ensure(matches.length===1,'KEYS_PENDING');const r=matches[0],ctx=r.body.context,issuer=historicalSnapshot(this.#snapshot,this.pins,ctx.issuer.roster_head),cert=activeCertificateForEvaluation(issuer.roster,ctx.issuer.device_id,'distribute-group-key');ensure(ctx.service_id===this.scope.service_id&&ctx.epoch_digest===info.epoch_digest&&same(ctx.membership_head,info.membership)&&same(ctx.recipient,activeRecipientForRosterEvaluation(issuer.roster,this.scope.device_id)),'GRANT_CONTEXT_MISMATCH');const key=openGroupKeyForEvaluation(wire(r),wire(ctx),cert,this.#keys.encryption.publicKey,this.#keys.encryption.privateKey);try{ensure(g.groupKeyCommitment({service_id:this.scope.service_id,group_id:info.group_id},key)===info.key_commitment,'INTEGRITY_FAILURE');await this.#commit({addKeys:[{service_id:this.scope.service_id,group_id:info.group_id,key_epoch:'0',epoch_digest:info.epoch_digest,group_secret:b64(key)}]});return {group_id:info.group_id,state:'keys-local-saved'};}finally{sodium.memzero(key);}
  }
  throw Error('INVALID_DEVICE_COMMAND');
 }
 #transcript(){const p=this.#state.pending;ensure(p?.offer&&p.response,'PAIRING_ORDER');return {purpose:'pairing-transcript',contract:'p02-state-c1',protocol:'anynote',protocol_version:1,invitation:p.invitation,offer:p.offer,response:p.response};}
}
