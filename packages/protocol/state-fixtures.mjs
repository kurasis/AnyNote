import { readFileSync,writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import sodium from 'libsodium-wrappers-sumo';
import { wire } from './src/identity-codec.mjs';
import { verifyRootIdentity,identityDetails,deriveRoot,senderForCertificate,sealGroupKeyForEvaluation } from './src/identity-crypto.mjs';
import { stateDecode,stateDigest } from './src/state-codec.mjs';
import * as r from './src/roster.mjs';
import * as e from './src/enrollment.mjs';
import { EvaluationAuthority } from './src/evaluation-authority.mjs';
import * as channel from './src/pairing-channel.mjs';
import { publicSeed,fixturePath as identityFixturePath } from './crypto-vectors.mjs';
import { sha256 } from './src/codec.mjs';
await sodium.ready;
const b64=b=>Buffer.from(b).toString('base64url');
export const stateFixturePath=new URL('../../fixtures/protocol/p02/state-vectors.json',import.meta.url);
export function publicDevice(index) {
  const signing=sodium.crypto_sign_seed_keypair(publicSeed(index*16+3)),encryption=sodium.crypto_box_seed_keypair(publicSeed(index*16+11));
  return {signing,encryption,body:{device_id:b64(publicSeed(index*16+7).slice(0,16)),signing_key:b64(signing.publicKey),encryption_key:b64(encryption.publicKey),
    capabilities:['delegate-device','distribute-group-key','receive-group-key','sign-content']}};
}
export function fixtureBase() {
  const v=JSON.parse(readFileSync(identityFixturePath)),identity=verifyRootIdentity(wire(v.outputs.identity),wire(v.outputs.pin));
  const root=deriveRoot(Buffer.from(v.input.root_secret_hex,'hex'),wire(v.input.context));
  const roster=r.newRosterForEvaluation(identity),server=new EvaluationAuthority(roster);
  return {v,identity,root,roster,server,now:10000n};
}
export function registerFixture(base,index=0,limit='5') {
  const device=publicDevice(index),session=base.server.authenticateForEvaluation(base.now),challenge=base.server.issueChallenge(session,'register',wire(device.body),base.now);
  const event=e.rootEventForEvaluation(base.roster,challenge,device,base.root.signing.privateKey,limit);
  const result=base.server.submitRootTransition(session,event,base.now);
  return {device,session,challenge,event,result};
}
export function prepareEnrollment(base,approver,index,mode='new-device-offer') {
  const device=publicDevice(index),session=base.server.authenticateForEvaluation(base.now),op=e.randomOperationId(),expiry=String(base.now+600000n);
  const binding=base.server.sessionDetails(session,base.now).binding;
  const invitation=mode==='existing-device-invitation'?e.invitationForEvaluation(base.roster,approver.device.body.device_id,op,expiry,approver.device.signing.privateKey):null;
  const offer=e.offerForEvaluation(base.roster,wire(device.body),binding,op,expiry,device.signing.privateKey,invitation);
  const key=channel.generatePairingKey(),qr=channel.pairingQr(mode,invitation??offer,key);
  const newChannel=channel.scannedChannelForEvaluation(qr,'new-device'),oldChannel=channel.scannedChannelForEvaluation(qr,'approver'),frames=[];
  if(invitation) {
    const frame=channel.sealPairingFrame(newChannel,'new-device-offer',offer,stateDigest('invitation',invitation));
    const opened=channel.openPairingFrame(oldChannel,frame,'new-device-offer',stateDigest('invitation',invitation));
    frames.push({frame:stateDecode('frame',frame),expected:stateDecode('offer',opened)});
  }
  const {response,transcript}=e.responseForEvaluation(base.roster,offer,approver.device.body.device_id,approver.device.signing.privateKey,invitation,base.now);
  const responseFrame=channel.sealPairingFrame(oldChannel,'approver-response',response,stateDigest('offer',offer));
  const responseOpened=channel.openPairingFrame(newChannel,responseFrame,'approver-response',stateDigest('offer',offer));
  frames.push({frame:stateDecode('frame',responseFrame),expected:stateDecode('response',responseOpened)});
  const approval=e.approvalForEvaluation(base.roster,transcript,approver.device.signing.privateKey,base.now),td=stateDigest('transcript',transcript);
  const approvalFrame=channel.sealPairingFrame(oldChannel,'approver-approval',approval,td);
  const approvalOpened=channel.openPairingFrame(newChannel,approvalFrame,'approver-approval',td);
  frames.push({frame:stateDecode('frame',approvalFrame),expected:stateDecode('approval',approvalOpened)});
  const staged=base.server.stageEnrollment(approver.session,session,transcript,approval,base.now);
  const confirmation=e.confirmationForEvaluation(base.roster,transcript,approval,device.encryption.privateKey,device.signing.privateKey,base.now);
  const confirmationFrame=channel.sealPairingFrame(newChannel,'new-device-confirmation',confirmation,td);
  const confirmationOpened=channel.openPairingFrame(oldChannel,confirmationFrame,'new-device-confirmation',td);
  frames.push({frame:stateDecode('frame',confirmationFrame),expected:stateDecode('confirmation',confirmationOpened)});
  channel.closePairingChannel(newChannel);channel.closePairingChannel(oldChannel);sodium.memzero(key);
  const event=e.enrollmentEventForEvaluation(base.roster,transcript,approval,confirmation,device.signing.privateKey);
  return {device,session,qr,frames,transcript,approval,confirmation,event,staged};
}
export function activateFixture(base,pair) { return base.server.submitEnrollment(pair.session,pair.event,base.now); }
export function writeStateFixture() {
  const base=fixtureBase(),first=registerFixture(base),events=[stateDecode('event',first.event)],snapshots=[r.rosterDetails(base.roster)];
  const second=prepareEnrollment(base,first,1);activateFixture(base,second);events.push(stateDecode('event',second.event));snapshots.push(r.rosterDetails(base.roster));
  const third=prepareEnrollment(base,second,2,'existing-device-invitation');activateFixture(base,third);events.push(stateDecode('event',third.event));snapshots.push(r.rosterDetails(base.roster));
  const context={purpose:'group-key-distribution',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,service_id:base.v.outputs.pin.service_id,
    group_id:b64(publicSeed(192).slice(0,16)),key_epoch:'1',epoch_digest:sha256(Buffer.from('PUBLIC synthetic policy/epoch not evaluated')),
    membership_head:{version:'0',digest:sha256(Buffer.from('PUBLIC policy prerequisite'))},operation_id:e.randomOperationId(),
    issuer:senderForCertificate(r.activeCertificateForEvaluation(base.roster,first.device.body.device_id),r.rosterDetails(base.roster).head),
    recipient:r.activeRecipientForRosterEvaluation(base.roster,third.device.body.device_id)};
  const grant=sealGroupKeyForEvaluation(wire(context),publicSeed(144),third.device.encryption.publicKey,first.device.signing.privateKey,r.activeCertificateForEvaluation(base.roster,first.device.body.device_id));
  const revoked=e.revokeEventForEvaluation(base.roster,first.device.body.device_id,[second.device.body.device_id],first.device.signing.privateKey);
  base.server.submitRevoke(first.session,revoked,base.now);events.push(stateDecode('event',revoked));snapshots.push(r.rosterDetails(base.roster));
  const recovered=publicDevice(3),recoverySession=base.server.authenticateForEvaluation(base.now),challenge=base.server.issueChallenge(recoverySession,'reset',wire(recovered.body),base.now);
  const reset=e.rootEventForEvaluation(base.roster,challenge,recovered,base.root.signing.privateKey);
  base.server.submitRootTransition(recoverySession,reset,base.now);events.push(stateDecode('event',reset));snapshots.push(r.rosterDetails(base.roster));
  const fixture={status:'PUBLIC_SYNTHETIC_KEYS_AND_CHALLENGES_NEVER_PRODUCT_AUTH',contract:'p02-state-c1',identity:base.v.outputs.identity,pin:base.v.outputs.pin,
    public_device_seed_profile:'index i: signing seed bytes (16*i+3)..+31; encryption (16*i+11)..+31; public only',
    inputs:{events,pairing_channels:[second,third].map(pair=>({qr:stateDecode('qr',pair.qr),frames:pair.frames})),grant_context:context,grant:JSON.parse(grant)},
    outputs:{snapshots,event_digests:events.map(ev=>stateDigest('event',wire(ev))),final_head:r.rosterDetails(base.roster).head}};
  writeFileSync(stateFixturePath,JSON.stringify(fixture,null,2)+'\n');return fixture;
}
export function checkStateFixture(fixture) {
  const identity=verifyRootIdentity(wire(fixture.identity),wire(fixture.pin)),roster=r.newRosterForEvaluation(identity);
  fixture.inputs.events.forEach((event,index)=>{
    r.applyRosterEventForEvaluation(roster,wire(event));
    if(JSON.stringify(r.rosterDetails(roster))!==JSON.stringify(fixture.outputs.snapshots[index])) throw new Error('STATE_FIXTURE_DRIFT');
    if(stateDigest('event',wire(event))!==fixture.outputs.event_digests[index])throw new Error('EVENT_DIGEST_DRIFT');
  });
  r.replayRosterForEvaluation(identity,fixture.inputs.events.map(wire),wire(fixture.outputs.final_head));
  for(const pairing of fixture.inputs.pairing_channels) {
    const key=Buffer.from(pairing.qr.channel_key,'base64url');
    for(const {frame,expected} of pairing.frames) {
      const role=frame.context.message.startsWith('new-device-')?'approver':'new-device';
      const token=channel.scannedChannelForEvaluation(wire(pairing.qr),role);
      const opened=channel.openPairingFrame(token,wire(frame),frame.context.message,frame.context.anchor_digest);
      if(JSON.stringify(JSON.parse(opened))!==JSON.stringify(expected))throw new Error('CHANNEL_FIXTURE_DRIFT');
      channel.closePairingChannel(token);
    }
    sodium.memzero(key);
  }
  return {status:'PASS',events:fixture.inputs.events.length,qr_directions:2,channel_frames:fixture.inputs.pairing_channels.reduce((n,p)=>n+p.frames.length,0),
    device_roster_authorization:'VERIFIED_FROM_PINNED_CHAIN',account_login_and_durable_transactions:'SIMULATED_NOT_IMPLEMENTED',group_authorization:'NOT_EVALUATED'};
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
  const fixture=process.argv.includes('--write')?writeStateFixture():JSON.parse(readFileSync(stateFixturePath));
  console.log(JSON.stringify(checkStateFixture(fixture)));
}
