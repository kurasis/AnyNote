import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import sodium from 'libsodium-wrappers-sumo';
import { ContractError } from '../src/strict-json.mjs';
import { wire } from '../src/identity-codec.mjs';
import { certificateDetails, senderForCertificate, sealGroupKeyForEvaluation } from '../src/identity-crypto.mjs';
import { stateDecode,stateDigest,stateCommon,stateDomain,stateEncode } from '../src/state-codec.mjs';
import * as r from '../src/roster.mjs';
import * as e from '../src/enrollment.mjs';
import * as ch from '../src/pairing-channel.mjs';
import { answerPossessionChallenge,EvaluationAuthority } from '../src/evaluation-authority.mjs';
import { fixtureBase,registerFixture,prepareEnrollment,activateFixture,publicDevice,stateFixturePath,checkStateFixture } from '../state-fixtures.mjs';
await sodium.ready;
const clone=structuredClone,b64=b=>Buffer.from(b).toString('base64url');
const rejects=(fn,code)=>assert.throws(fn,error=>error instanceof ContractError&&(!code||error.code===code));
function base(limit='5') { const b=fixtureBase();b.first=registerFixture(b,0,limit);return b; }
const changeEvent=(bytes,change,key)=>{const event=stateDecode('event',bytes);change(event.body);return r.signStateRecord('event',wire(event.body),key);};

test('frozen public state/transcript/channel inputs reproduce five heads and both QR directions',()=>assert.equal(checkStateFixture(JSON.parse(readFileSync(stateFixturePath))).status,'PASS'));
test('independent root register activates only a freshly proved device and bound session',()=>{
 const b=base();assert.equal(r.rosterDetails(b.roster).head.version,'0');assert.equal(b.server.requireTrustedSession(b.first.session,b.now).device_id,b.first.device.body.device_id);
 assert.equal(b.first.result.durable_transaction,'NOT_IMPLEMENTED');
});
for(const mode of ['new-device-offer','existing-device-invitation'])test(`${mode}: approval is provisional, activation requires both key proofs`,()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1,mode);
 assert.deepEqual(p.staged,{state:'APPROVED',device_active:false,session_upgrade:false,group_key_release:false});
 rejects(()=>r.activeRecipientForRosterEvaluation(b.roster,p.device.body.device_id),'DEVICE_NOT_ACTIVE');
 rejects(()=>b.server.requireTrustedSession(p.session,b.now),'RESTRICTED_SESSION');
 activateFixture(b,p);assert.equal(b.server.requireTrustedSession(p.session,b.now).device_id,p.device.body.device_id);
 assert.equal(r.rosterDetails(b.roster).devices.length,2);
});
test('activation receipt retry is byte-identical; changed same operation and other session denied',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),first=activateFixture(b,p),count=r.rosterDetails(b.roster).event_count;
 assert.deepEqual(b.server.submitEnrollment(p.session,p.event,b.now),first);assert.equal(r.rosterDetails(b.roster).event_count,count);
 const changed=changeEvent(p.event,x=>x.payload.confirmation.body.challenge_response=b64(new Uint8Array(32)),p.device.signing.privateKey);
 rejects(()=>b.server.submitEnrollment(p.session,changed,b.now),'OPERATION_ID_CONFLICT');
 const other=b.server.authenticateForEvaluation(b.now);rejects(()=>b.server.submitEnrollment(other,p.event,b.now),'RECEIPT_SESSION_MISMATCH');
});
test('root transition exact receipt does not create another identity; bootstrap unavailable afterward',()=>{
 const b=base();assert.deepEqual(b.server.submitRootTransition(b.first.session,b.first.event,b.now),b.first.result);
 const other=b.server.authenticateForEvaluation(b.now);rejects(()=>b.server.issueChallenge(other,'register',wire(publicDevice(1).body),b.now),'INVALID_ROOT_TRANSITION');
 rejects(()=>r.applyRosterEventForEvaluation(b.roster,b.first.event),'OPERATION_REPLAY');
});
test('missing encryption/signing possession cannot activate and failed operation leaves roster unchanged',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),before=r.rosterDetails(b.roster);
 const wrong=changeEvent(p.event,x=>{x.payload.confirmation.body.challenge_response=b64(new Uint8Array(32));
   const body=x.payload.confirmation.body;x.payload.confirmation=stateDecode('confirmation',r.signStateRecord('confirmation',wire(body),p.device.signing.privateKey));},p.device.signing.privateKey);
 rejects(()=>b.server.submitEnrollment(p.session,wrong,b.now),'ENCRYPTION_POSSESSION_MISMATCH');assert.deepEqual(r.rosterDetails(b.roster),before);
 const wrongSign=changeEvent(p.event,x=>x.payload.confirmation.signature=b64(new Uint8Array(64)),p.device.signing.privateKey);
 rejects(()=>b.server.submitEnrollment(p.session,wrongSign,b.now),'SIGNATURE_INVALID');assert.deepEqual(r.rosterDetails(b.roster),before);
 rejects(()=>e.confirmationForEvaluation(b.roster,p.transcript,p.approval,b.first.device.encryption.privateKey,p.device.signing.privateKey,b.now),'ENCRYPTION_POSSESSION_MISMATCH');
});
for(const field of ['account_id','service_id','root_fingerprint','generation','roster','session_binding','device','invitation_digest'])test(`offer ${field} cannot be substituted by relay`,()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),t=stateDecode('transcript',p.transcript),before=r.rosterDetails(b.roster);
 if(field==='generation')t.offer.body[field]='1';else if(field==='roster')t.offer.body[field].version='1';
 else if(field==='device')t.offer.body.device.encryption_key=b64(new Uint8Array(32));
 else if(field==='invitation_digest')t.offer.body[field]=b64(new Uint8Array(32));
 else t.offer.body[field]=b64(new Uint8Array(field.endsWith('_id')?16:32));
 rejects(()=>r.verifyPairingTranscript(b.roster,wire(t),b.now));assert.deepEqual(r.rosterDetails(b.roster),before);
});
test('valid changed offer cannot reuse an old signed response',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),t=stateDecode('transcript',p.transcript);t.offer.body.nonce=b64(new Uint8Array(32));
 t.offer=stateDecode('offer',r.signStateRecord('offer',wire(t.offer.body),p.device.signing.privateKey));
 rejects(()=>r.verifyPairingTranscript(b.roster,wire(t),b.now),'PAIRING_TRANSCRIPT_MISMATCH');
});
test('pairing expiry bound and server clock regression reject safely',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1);
 rejects(()=>b.server.submitEnrollment(p.session,p.event,b.now+600000n),'PAIRING_EXPIRED_OR_OUT_OF_RANGE');
 rejects(()=>b.server.requireTrustedSession(b.first.session,b.now),'INVALID_OR_REGRESSED_CLOCK');
 const fresh=base();rejects(()=>r.pairingWindow(String(fresh.now+600001n),fresh.now),'PAIRING_EXPIRED_OR_OUT_OF_RANGE');
});
test('device cap is root-signed, enforced without eviction and reset cannot silently increase it',()=>{
 const b=base('1');rejects(()=>prepareEnrollment(b,b.first,1),'DEVICE_LIMIT');assert.equal(r.rosterDetails(b.roster).devices.length,1);
 const s=b.server.authenticateForEvaluation(b.now),d=publicDevice(2),c=b.server.issueChallenge(s,'reset',wire(d.body),b.now);
 const event=e.rootEventForEvaluation(b.roster,c,d,b.root.signing.privateKey,'2');
 rejects(()=>b.server.submitRootTransition(s,event,b.now),'DEVICE_LIMIT_POLICY_MISMATCH');assert.equal(r.rosterDetails(b.roster).generation,'0');
});
test('head advance invalidates other provisional approvals; no blind reuse',()=>{
 const b=base(),one=prepareEnrollment(b,b.first,1),other=prepareEnrollment(b,b.first,2);activateFixture(b,one);
 rejects(()=>b.server.submitEnrollment(other.session,other.event,b.now),'PENDING_APPROVAL_REQUIRED');
 rejects(()=>r.verifyEnrollmentApproval(b.roster,other.transcript,other.approval,b.now),'ROSTER_CHANGED');
 assert.equal(r.rosterDetails(b.roster).pending_operations.length,0);
});
test('explicit cancel and expiry are terminal for the pending operation',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),op=stateDecode('transcript',p.transcript).offer.body.operation_id;
 b.server.cancelEnrollment(p.session,op,b.now);rejects(()=>b.server.submitEnrollment(p.session,p.event,b.now),'PENDING_APPROVAL_REQUIRED');
 rejects(()=>r.stageEnrollmentForEvaluation(b.roster,p.transcript,p.approval,b.now),'DEVICE_ID_REUSE');
 const expired=prepareEnrollment(b,b.first,2);assert.equal(r.expirePendingEnrollmentsForEvaluation(b.roster,b.now+600000n).length,1);
 assert.equal(r.rosterDetails(b.roster).pending_operations.length,0);
});
test('compromise revoke computes transitive closure and invalidates both descendant sessions',()=>{
 const b=base(),parent=prepareEnrollment(b,b.first,1);activateFixture(b,parent);const child=prepareEnrollment(b,parent,2);activateFixture(b,child);
 const event=e.revokeEventForEvaluation(b.roster,b.first.device.body.device_id,[parent.device.body.device_id],b.first.device.signing.privateKey);
 const result=b.server.submitRevoke(b.first.session,event,b.now);
 assert.deepEqual(result.revoked_device_ids,[parent.device.body.device_id,child.device.body.device_id].sort());
 for(const p of [parent,child]) {rejects(()=>r.activeRecipientForRosterEvaluation(b.roster,p.device.body.device_id),'DEVICE_NOT_ACTIVE');rejects(()=>b.server.requireTrustedSession(p.session,b.now),'SESSION_REVOKED_OR_EXPIRED');}
 assert.equal(certificateDetails(r.historicalCertificateForEvaluation(b.roster,child.device.body.device_id)).body.device_id,child.device.body.device_id);
 assert.equal(result.groups_require_maintenance,true);
});
test('a surviving actor must sign exact descendant closure; omitted child and self-revoke fail atomically',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1);activateFixture(b,p);const child=prepareEnrollment(b,p,2);activateFixture(b,child);
 const good=e.revokeEventForEvaluation(b.roster,b.first.device.body.device_id,[p.device.body.device_id],b.first.device.signing.privateKey),before=r.rosterDetails(b.roster);
 const bad=changeEvent(good,x=>x.payload.affected_devices=[p.device.body.device_id],b.first.device.signing.privateKey);
 rejects(()=>b.server.submitRevoke(b.first.session,bad,b.now),'DESCENDANT_CLOSURE_MISMATCH');assert.deepEqual(r.rosterDetails(b.roster),before);
 const self=e.revokeEventForEvaluation(b.roster,p.device.body.device_id,[p.device.body.device_id],p.device.signing.privateKey);
 rejects(()=>b.server.submitRevoke(p.session,self,b.now),'REVOKER_IN_CLOSURE');assert.deepEqual(r.rosterDetails(b.roster),before);
});
test('revoked delegate cannot approve, sign a new roster event or receive a fresh session challenge',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1);activateFixture(b,p);
 b.server.submitRevoke(b.first.session,e.revokeEventForEvaluation(b.roster,b.first.device.body.device_id,[p.device.body.device_id],b.first.device.signing.privateKey),b.now);
 rejects(()=>prepareEnrollment(b,p,2),'DEVICE_NOT_ACTIVE');
 const newSession=b.server.authenticateForEvaluation(b.now);rejects(()=>b.server.issueChallenge(newSession,'device-proof',wire(p.device.body),b.now),'DEVICE_NOT_ACTIVE');
});
test('reset advances generation, revokes all old sessions/pending before recovery recipient access',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1);activateFixture(b,p);const pending=prepareEnrollment(b,p,2);
 const d=publicDevice(3),s=b.server.authenticateForEvaluation(b.now),c=b.server.issueChallenge(s,'reset',wire(d.body),b.now);
 rejects(()=>b.server.requireTrustedSession(s,b.now),'RESTRICTED_SESSION');
 const event=e.rootEventForEvaluation(b.roster,c,d,b.root.signing.privateKey),out=b.server.submitRootTransition(s,event,b.now);
 assert.equal(out.generation,'1');assert.equal(b.server.requireTrustedSession(s,b.now).device_id,d.body.device_id);
 for(const old of [b.first.session,p.session,pending.session])rejects(()=>b.server.requireTrustedSession(old,b.now),'SESSION_REVOKED_OR_EXPIRED');
 assert.equal(r.recoveryRecipientForRosterEvaluation(b.roster).recovery_generation,'1');assert.equal(r.rosterDetails(b.roster).pending_operations.length,0);
 assert.equal(out.groups_require_maintenance,true);
});
test('concurrent root resets consume exact session/challenge and loser cannot reuse old generation',()=>{
 const b=base(),a=publicDevice(2),d=publicDevice(3),s1=b.server.authenticateForEvaluation(b.now),s2=b.server.authenticateForEvaluation(b.now);
 const c1=b.server.issueChallenge(s1,'reset',wire(a.body),b.now),c2=b.server.issueChallenge(s2,'reset',wire(d.body),b.now);
 const e1=e.rootEventForEvaluation(b.roster,c1,a,b.root.signing.privateKey),e2=e.rootEventForEvaluation(b.roster,c2,d,b.root.signing.privateKey);
 rejects(()=>b.server.submitRootTransition(s2,e1,b.now),'ISSUED_CHALLENGE_REQUIRED');b.server.submitRootTransition(s1,e1,b.now);
 rejects(()=>b.server.submitRootTransition(s2,e2,b.now),'SESSION_REVOKED_OR_EXPIRED');rejects(()=>r.applyRosterEventForEvaluation(b.roster,e2),'ROSTER_CHANGED');
});
test('root replacement/wrong session/expired reset do not mutate the current roster',()=>{
 const b=base(),d=publicDevice(2),s=b.server.authenticateForEvaluation(b.now),c=b.server.issueChallenge(s,'reset',wire(d.body),b.now),event=e.rootEventForEvaluation(b.roster,c,d,b.root.signing.privateKey),before=r.rosterDetails(b.roster);
 const fake=changeEvent(event,x=>x.root_fingerprint=b64(new Uint8Array(32)),b.root.signing.privateKey);
 rejects(()=>b.server.submitRootTransition(s,fake,b.now),'ROSTER_CONTEXT_MISMATCH');assert.deepEqual(r.rosterDetails(b.roster),before);
 rejects(()=>b.server.submitRootTransition(s,event,b.now+60000n),'CHALLENGE_EXPIRED');assert.deepEqual(r.rosterDetails(b.roster),before);
});
test('one-use normal device proof binds restricted session, current keys and challenge',()=>{
 const b=base(),s=b.server.authenticateForEvaluation(b.now),c=b.server.issueChallenge(s,'device-proof',wire(b.first.device.body),b.now);
 const proof=answerPossessionChallenge(c,b.first.device.encryption.privateKey,b.first.device.signing.privateKey);
 assert.equal(b.server.proveSession(s,c,proof,b.now).device_id,b.first.device.body.device_id);
 rejects(()=>b.server.proveSession(s,c,proof,b.now),'RESTRICTED_SESSION_REQUIRED');
 const s2=b.server.authenticateForEvaluation(b.now);rejects(()=>b.server.proveSession(s2,c,proof,b.now),'ISSUED_CHALLENGE_REQUIRED');
});
test('old device IDs and keys cannot be silently reused even after reset',()=>{
 const b=base(),s=b.server.authenticateForEvaluation(b.now),c=b.server.issueChallenge(s,'reset',wire(b.first.device.body),b.now),event=e.rootEventForEvaluation(b.roster,c,b.first.device,b.root.signing.privateKey);
 rejects(()=>b.server.submitRootTransition(s,event,b.now),'DEVICE_ID_REUSE');
});
test('pinned replay rejects missing/truncated/forked/regressed heads and malformed raw pin',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1);activateFixture(b,p);const inputs=r.rosterEvents(b.roster),head=r.rosterDetails(b.roster).head;
 assert.deepEqual(r.rosterDetails(r.replayRosterForEvaluation(b.identity,inputs,wire(head))).head,head);
 rejects(()=>r.replayRosterForEvaluation(b.identity,inputs.slice(0,1),wire(head)),'ROSTER_PIN_MISMATCH');
 const pin=clone(head);pin.digest=b64(new Uint8Array(32));rejects(()=>r.replayRosterForEvaluation(b.identity,inputs,wire(pin)),'ROSTER_PIN_MISMATCH');
 rejects(()=>r.replayRosterForEvaluation(b.identity,inputs,Buffer.from('{"version":"1","version":"0","digest":"x"}')),'DUPLICATE_PROPERTY');
});
test('roster-gated key delivery works only at current issuer and recipient heads',()=>{
 const fixture=JSON.parse(readFileSync(stateFixturePath)),identity=fixtureBase().identity,roster=r.newRosterForEvaluation(identity);
 for(const event of fixture.inputs.events.slice(0,3))r.applyRosterEventForEvaluation(roster,wire(event));
 const target=publicDevice(2),key=r.openGroupKeyWithRostersForEvaluation(wire(fixture.inputs.grant),wire(fixture.inputs.grant_context),roster,roster,target.encryption.publicKey,target.encryption.privateKey);
 assert.equal(key.length,32);assert.equal(r.checkGrantRostersForEvaluation(wire(fixture.inputs.grant),wire(fixture.inputs.grant_context),roster,roster).group_authorization,'NOT_EVALUATED');
 r.applyRosterEventForEvaluation(roster,wire(fixture.inputs.events[3]));
 rejects(()=>r.openGroupKeyWithRostersForEvaluation(wire(fixture.inputs.grant),wire(fixture.inputs.grant_context),roster,roster,target.encryption.publicKey,target.encryption.privateKey));
});
test('channel wrong key/AAD, modified header/tag, reflection/replay and nonfinal stream fail',()=>{
 const fixture=JSON.parse(readFileSync(stateFixturePath)),p=fixture.inputs.pairing_channels[0],f=p.frames[0].frame,kind=f.context.message,anchor=f.context.anchor_digest;
 const qr=clone(p.qr);qr.channel_key=b64(new Uint8Array(32));rejects(()=>ch.openPairingFrame(ch.scannedChannelForEvaluation(wire(qr),'new-device'),wire(f),kind,anchor),'CHANNEL_INTEGRITY_FAILURE');
 rejects(()=>ch.openPairingFrame(ch.scannedChannelForEvaluation(wire(p.qr),'approver'),wire(f),kind,anchor),'CHANNEL_REFLECTION');
 const token=ch.scannedChannelForEvaluation(wire(p.qr),'new-device');ch.openPairingFrame(token,wire(f),kind,anchor);rejects(()=>ch.openPairingFrame(token,wire(f),kind,anchor),'CHANNEL_REPLAY');ch.closePairingChannel(token);rejects(()=>ch.openPairingFrame(token,wire(f),kind,anchor),'CHANNEL_CLOSED');
 const bad=clone(f),bytes=Buffer.from(bad.ciphertext,'base64url');bytes[bytes.length-1]^=1;bad.ciphertext=b64(bytes);
 rejects(()=>ch.openPairingFrame(ch.scannedChannelForEvaluation(wire(p.qr),'new-device'),wire(bad),kind,anchor),'CHANNEL_INTEGRITY_FAILURE');
 const headerBad=clone(f),header=Buffer.from(f.header,'base64url');header[0]^=1;headerBad.header=b64(header);
 rejects(()=>ch.openPairingFrame(ch.scannedChannelForEvaluation(wire(p.qr),'new-device'),wire(headerBad),kind,anchor),'CHANNEL_INTEGRITY_FAILURE');
 const stream=sodium.crypto_secretstream_xchacha20poly1305_init_push(Buffer.from(p.qr.channel_key,'base64url'));
 const aad=Buffer.concat([stateDomain('aad','pairing-channel-frame'),stateEncode('channel-context',wire(f.context))]);
 const nonfinal={context:f.context,header:b64(stream.header),ciphertext:b64(sodium.crypto_secretstream_xchacha20poly1305_push(stream.state,wire(p.frames[0].expected),aad,sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE))};
 rejects(()=>ch.openPairingFrame(ch.scannedChannelForEvaluation(wire(p.qr),'new-device'),wire(nonfinal),kind,anchor),'CHANNEL_INTEGRITY_FAILURE');
 const aadBad=clone(f);aadBad.context.anchor_digest=b64(new Uint8Array(32));rejects(()=>ch.openPairingFrame(ch.scannedChannelForEvaluation(wire(p.qr),'new-device'),wire(aadBad),kind,anchor),'CHANNEL_CONTEXT_MISMATCH');
});
for(const kind of ['event','offer','approval','challenge','frame','qr'])test(`${kind} raw parser rejects duplicates, invalid Unicode, unknown fields and resource overflow`,()=>{
 rejects(()=>stateDecode(kind,Buffer.from('{"a":1,"\\u0061":2}')),'DUPLICATE_PROPERTY');rejects(()=>stateDecode(kind,Buffer.from('"\\ud800"')),'INVALID_UNICODE');
 rejects(()=>stateDecode(kind,wire({extra:true})),'SCHEMA_MISMATCH');rejects(()=>stateDecode(kind,Buffer.alloc(kind==='qr'?8193:65537)),'RESOURCE_LIMIT');
});

test('valid root signature and possession cannot consume an unissued challenge',()=>{
 const b=base(),d=publicDevice(2),other=new EvaluationAuthority(b.roster),otherSession=other.authenticateForEvaluation(b.now);
 const c=other.issueChallenge(otherSession,'reset',wire(d.body),b.now),event=e.rootEventForEvaluation(b.roster,c,d,b.root.signing.privateKey);
 const s=b.server.authenticateForEvaluation(b.now),before=r.rosterDetails(b.roster);
 rejects(()=>b.server.submitRootTransition(s,event,b.now),'ISSUED_CHALLENGE_REQUIRED');assert.deepEqual(r.rosterDetails(b.roster),before);
});
test('historical key reuse under a fresh ID and forged opaque handles fail closed',()=>{
 const b=base(),device=publicDevice(0);device.body.device_id=publicDevice(2).body.device_id;
 const s=b.server.authenticateForEvaluation(b.now),c=b.server.issueChallenge(s,'reset',wire(device.body),b.now),event=e.rootEventForEvaluation(b.roster,c,device,b.root.signing.privateKey);
 rejects(()=>b.server.submitRootTransition(s,event,b.now),'DEVICE_KEY_REUSE');
 rejects(()=>b.server.requireTrustedSession({status:'TRUSTED'},b.now),'SESSION_REQUIRED');
 rejects(()=>r.activeCertificateForEvaluation({device_roster_authorization:'VERIFIED_FROM_PINNED_CHAIN'},device.body.device_id),'ROSTER_PROOF_REQUIRED');
});
test('corrupt sealed proof returns a bounded failure before activating either session type',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),approval=stateDecode('approval',p.approval);
 approval.body.sealed_challenge=b64(new Uint8Array(48));
 const signed=r.signStateRecord('approval',wire(approval.body),b.first.device.signing.privateKey);
 rejects(()=>e.confirmationForEvaluation(b.roster,p.transcript,signed,p.device.encryption.privateKey,p.device.signing.privateKey,b.now),'ENCRYPTION_POSSESSION_MISMATCH');
 const s=b.server.authenticateForEvaluation(b.now),c=stateDecode('challenge',b.server.issueChallenge(s,'device-proof',wire(b.first.device.body),b.now));c.sealed_challenge=b64(new Uint8Array(48));
 rejects(()=>answerPossessionChallenge(wire(c),b.first.device.encryption.privateKey,b.first.device.signing.privateKey),'ENCRYPTION_POSSESSION_MISMATCH');
 assert.equal(b.server.sessionDetails(s,b.now).status,'RESTRICTED');
});
test('an unrelated restricted account-login session cannot cancel another enrollment',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),s=b.server.authenticateForEvaluation(b.now),op=stateDecode('transcript',p.transcript).offer.body.operation_id;
 rejects(()=>b.server.cancelEnrollment(s,op,b.now),'SESSION_BINDING_MISMATCH');
 activateFixture(b,p);assert.equal(b.server.requireTrustedSession(p.session,b.now).device_id,p.device.body.device_id);
});
test('an active delegate cannot amplify its certificate capabilities',()=>{
 const b=fixtureBase(),device=publicDevice(0);device.body.capabilities=['delegate-device'];
 const session=b.server.authenticateForEvaluation(b.now),challenge=b.server.issueChallenge(session,'register',wire(device.body),b.now);
 const event=e.rootEventForEvaluation(b.roster,challenge,device,b.root.signing.privateKey);b.server.submitRootTransition(session,event,b.now);
 rejects(()=>prepareEnrollment(b,{device,session},1),'CAPABILITY_ESCALATION');
});
test('expired account authentication/session cannot issue reset authorization',()=>{
 const b=base(),session=b.server.authenticateForEvaluation(b.now),device=publicDevice(2);
 rejects(()=>b.server.issueChallenge(session,'reset',wire(device.body),b.now+300001n),'RECENT_ACCOUNT_AUTH_REQUIRED');
 rejects(()=>b.server.requireTrustedSession(b.first.session,b.now+900000n),'SESSION_REVOKED_OR_EXPIRED');
});
test('cancelled enrollment requires fresh keys and a fresh restricted session',()=>{
 const b=base(),p=prepareEnrollment(b,b.first,1),t=stateDecode('transcript',p.transcript);b.server.cancelEnrollment(p.session,t.offer.body.operation_id,b.now);
 rejects(()=>prepareEnrollment(b,b.first,1),'DEVICE_ID_REUSE');
 const d=publicDevice(2),offer=e.offerForEvaluation(b.roster,wire(d.body),t.offer.body.session_binding,e.randomOperationId(),String(b.now+600000n),d.signing.privateKey);
 rejects(()=>e.responseForEvaluation(b.roster,offer,b.first.device.body.device_id,b.first.device.signing.privateKey,null,b.now),'ENROLLMENT_SESSION_REUSE');
 const fresh=prepareEnrollment(b,b.first,2);activateFixture(b,fresh);assert.equal(b.server.requireTrustedSession(fresh.session,b.now).device_id,d.body.device_id);
});
