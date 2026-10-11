// Test-only account-login/session/challenge ledger. Authentication is explicitly
// SIMULATED; no passkey/invitation DB, HTTP, durable commit or production session.
import sodium from 'libsodium-wrappers-sumo';
import { ContractError, requireCondition as check } from './strict-json.mjs';
import { wire, same } from './identity-codec.mjs';
import { certificateDetails } from './identity-crypto.mjs';
import { stateDecode as decode, stateEncode as encode, stateDigest as digest, stateCommon as common } from './state-codec.mjs';
import { rosterDetails, rosterScope, activeCertificateForEvaluation, signStateRecord,
  stageEnrollmentForEvaluation, pendingEnrollmentForEvaluation, applyRosterEventForEvaluation,
  verifyDevicePossessionForEvaluation, cancelPendingEnrollmentForEvaluation } from './roster.mjs';
await sodium.ready;
const ledgers=new WeakMap(), b64=b=>Buffer.from(b).toString('base64url'), un64=s=>Buffer.from(s,'base64url');
function ledger(server) { check(ledgers.has(server),'EVALUATION_SERVER_REQUIRED');return ledgers.get(server); }
function clock(s,now) { check(typeof now==='bigint'&&now>=s.lastNow&&now<=9223372036854775807n,'INVALID_OR_REGRESSED_CLOCK');s.lastNow=now; }
function session(s,token,now) { clock(s,now);check(s.sessions.has(token),'SESSION_REQUIRED');const value=s.sessions.get(token);check(value.status!=='REVOKED'&&now<value.expiresAt,'SESSION_REVOKED_OR_EXPIRED');return value; }
function trusted(s,token,now) {
  const value=session(s,token,now), roster=rosterDetails(s.roster);
  check(value.status==='TRUSTED'&&value.generation===roster.generation,'RESTRICTED_SESSION');
  activeCertificateForEvaluation(s.roster,value.deviceId);
  return value;
}
function receipt(s,eventBytes,binding) {
  const event=decode('event',eventBytes), stored=s.receipts.get(event.body.operation_id);
  if(!stored)return null;
  check(stored.eventDigest===digest('event',eventBytes),'OPERATION_ID_CONFLICT');
  check(stored.binding===binding,'RECEIPT_SESSION_MISMATCH');
  return structuredClone(stored.result);
}
function commit(s,eventBytes,owner,effect,now) {
  const result=applyRosterEventForEvaluation(s.roster,eventBytes,now);
  for(const [token,value] of s.sessions) {
    if(effect==='reset'&&token!==owner) value.status='REVOKED';
    else if(result.revoked_device_ids.includes(value.deviceId)) value.status='REVOKED';
  }
  for(const value of s.challenges.values()) if(!value.used)value.cancelled=true;
  return result;
}
function saveReceipt(s,eventBytes,binding,result) {
  s.receipts.set(decode('event',eventBytes).body.operation_id,{eventDigest:digest('event',eventBytes),binding,result:structuredClone(result)});
  return result;
}
export class EvaluationAuthority {
  constructor(rosterToken) {
    rosterDetails(rosterToken);
    ledgers.set(this,{roster:rosterToken,sessions:new Map(),challenges:new Map(),receipts:new Map(),lastNow:0n});
  }
  authenticateForEvaluation(now) {
    const s=ledger(this);clock(s,now);check(s.sessions.size<256,'RESOURCE_LIMIT');
    const token=Object.freeze({authentication:'SIMULATED_ACCOUNT_LOGIN',scope:'NO_PRODUCT_SESSION'});
    s.sessions.set(token,{binding:b64(sodium.randombytes_buf(32)),status:'RESTRICTED',authenticatedAt:now,expiresAt:now+900000n,deviceId:null,generation:null});
    return token;
  }
  sessionDetails(token,now) { const s=ledger(this),value=session(s,token,now);return {binding:value.binding,status:value.status,device_id:value.deviceId,generation:value.generation,authentication:'SIMULATED_ACCOUNT_LOGIN'}; }
  requireTrustedSession(token,now) {
    const s=ledger(this),value=trusted(s,token,now);
    return {device_id:value.deviceId,roster:rosterDetails(s.roster).head,device_roster_authorization:'VERIFIED_FROM_LOCAL_CHAIN',group_authorization:'NOT_EVALUATED',authentication:'SIMULATED_ACCOUNT_LOGIN'};
  }
  issueChallenge(token,intent,deviceBytes,now) {
    const s=ledger(this),value=session(s,token,now),r=rosterDetails(s.roster),device=decode('device',deviceBytes);
    check(value.status==='RESTRICTED','RESTRICTED_SESSION_REQUIRED');
    check(now-value.authenticatedAt<=300000n,'RECENT_ACCOUNT_AUTH_REQUIRED');
    check(s.challenges.size<256,'RESOURCE_LIMIT');
    check(['register','reset','device-proof'].includes(intent),'UNSUPPORTED_PURPOSE');
    check(intent==='register'?!r.head:!!r.head,'INVALID_ROOT_TRANSITION');
    if(intent==='device-proof') {
      const cert=certificateDetails(activeCertificateForEvaluation(s.roster,device.device_id));
      check(device.signing_key===cert.body.device_signing_key&&device.encryption_key===cert.body.device_encryption_key&&same(device.capabilities,cert.body.capabilities),'DEVICE_KEYS_MISMATCH');
    }
    const context=decode('challenge-context',wire({...common('device-possession-challenge'),...rosterScope(s.roster),intent,
      challenge_id:b64(sodium.randombytes_buf(16)),session_binding:value.binding,generation:r.generation,roster:r.head,
      nonce:b64(sodium.randombytes_buf(32)),device,expires_at:String(now+60000n)}));
    const secret=sodium.randombytes_buf(32), plain=encode('challenge-plaintext',wire({purpose:'device-encryption-proof',context,secret:b64(secret)}));
    let bytes;
    try { bytes=encode('challenge',wire({context,sealed_challenge:b64(sodium.crypto_box_seal(plain,un64(device.encryption_key))),challenge_digest:digest('challenge-plaintext',plain)})); }
    finally { sodium.memzero(secret);sodium.memzero(plain); }
    s.challenges.set(context.challenge_id,{token,bytes,used:false,cancelled:false});
    return bytes;
  }
  stageEnrollment(approverSession,newSession,transcriptBytes,approvalBytes,now) {
    const s=ledger(this),actor=trusted(s,approverSession,now),newValue=session(s,newSession,now),t=decode('transcript',transcriptBytes);
    check(newValue.status==='RESTRICTED'&&newValue.binding===t.offer.body.session_binding,'SESSION_BINDING_MISMATCH');
    check(actor.deviceId===t.response.body.approver.device_id,'SESSION_DEVICE_MISMATCH');
    return stageEnrollmentForEvaluation(s.roster,transcriptBytes,approvalBytes,now);
  }
  cancelEnrollment(token,operationId,now) {
    const s=ledger(this),value=session(s,token,now),pending=pendingEnrollmentForEvaluation(s.roster,operationId),t=decode('transcript',pending.transcript);
    check(value.binding===t.offer.body.session_binding||(value.status==='TRUSTED'&&value.deviceId===t.response.body.approver.device_id),'SESSION_BINDING_MISMATCH');
    return cancelPendingEnrollmentForEvaluation(s.roster,operationId);
  }
  submitEnrollment(token,eventBytes,now) {
    const s=ledger(this),value=session(s,token,now),cached=receipt(s,eventBytes,value.binding);if(cached)return cached;
    check(value.status==='RESTRICTED','RESTRICTED_SESSION_REQUIRED');
    const event=decode('event',eventBytes);check(event.body.kind==='enroll','UNSUPPORTED_PURPOSE');
    const pending=pendingEnrollmentForEvaluation(s.roster,event.body.operation_id);
    check(same(decode('transcript',pending.transcript),event.body.payload.transcript)&&same(decode('approval',pending.approval),event.body.payload.approval),'APPROVAL_CONTEXT_MISMATCH');
    check(value.binding===event.body.payload.confirmation.body.session_binding,'SESSION_BINDING_MISMATCH');
    const result=commit(s,eventBytes,token,'enroll',now);
    value.status='TRUSTED';value.deviceId=result.activated_device_id;value.generation=result.generation;
    return saveReceipt(s,eventBytes,value.binding,result);
  }
  submitRootTransition(token,eventBytes,now) {
    const s=ledger(this),value=session(s,token,now),cached=receipt(s,eventBytes,value.binding);if(cached)return cached;
    check(value.status==='RESTRICTED','RESTRICTED_SESSION_REQUIRED');
    check(now-value.authenticatedAt<=300000n,'RECENT_ACCOUNT_AUTH_REQUIRED');
    const event=decode('event',eventBytes);check(['register','reset'].includes(event.body.kind),'UNSUPPORTED_PURPOSE');
    const challenge=event.body.payload.challenge;
    const issued=issuedChallenge(s,token,challenge,now);
    check(challenge.context.intent===event.body.kind&&challenge.context.session_binding===value.binding,'CHALLENGE_CONTEXT_MISMATCH');
    const result=commit(s,eventBytes,token,event.body.kind,now);issued.used=true;
    value.status='TRUSTED';value.deviceId=result.activated_device_id;value.generation=result.generation;
    return saveReceipt(s,eventBytes,value.binding,result);
  }
  submitRevoke(token,eventBytes,now) {
    const s=ledger(this),value=trusted(s,token,now),cached=receipt(s,eventBytes,value.binding);if(cached)return cached;
    const event=decode('event',eventBytes);
    check(event.body.kind==='revoke'&&event.body.signer===value.deviceId,'SESSION_DEVICE_MISMATCH');
    const result=commit(s,eventBytes,token,'revoke',now);
    return saveReceipt(s,eventBytes,value.binding,result);
  }
  proveSession(token,challengeBytes,proofBytes,now) {
    const s=ledger(this),value=session(s,token,now),challenge=decode('challenge',challengeBytes);
    check(value.status==='RESTRICTED','RESTRICTED_SESSION_REQUIRED');
    const issued=issuedChallenge(s,token,challenge,now),r=rosterDetails(s.roster);
    check(challenge.context.intent==='device-proof'&&challenge.context.generation===r.generation&&same(challenge.context.roster,r.head),'CHALLENGE_CONTEXT_MISMATCH');
    const proof=verifyDevicePossessionForEvaluation(s.roster,challengeBytes,proofBytes);
    activeCertificateForEvaluation(s.roster,proof.device_id);check(proof.session_binding===value.binding,'SESSION_BINDING_MISMATCH');
    issued.used=true;value.status='TRUSTED';value.deviceId=proof.device_id;value.generation=r.generation;
    return this.requireTrustedSession(token,now);
  }
}
function issuedChallenge(s,token,challenge,now) {
  const issued=s.challenges.get(challenge.context.challenge_id);
  check(issued&&issued.token===token,'ISSUED_CHALLENGE_REQUIRED');
  check(!issued.used&&!issued.cancelled,'CHALLENGE_CONSUMED_OR_STALE');
  check(same(decode('challenge',issued.bytes),challenge),'CHALLENGE_CONTEXT_MISMATCH');
  check(BigInt(challenge.context.expires_at)>now,'CHALLENGE_EXPIRED');return issued;
}
export function answerPossessionChallenge(challengeBytes, encryptionPrivateKey, signingPrivateKey) {
  const challenge=decode('challenge',challengeBytes);let plaintext;
  try { plaintext=sodium.crypto_box_seal_open(un64(challenge.sealed_challenge),un64(challenge.context.device.encryption_key),encryptionPrivateKey); check(plaintext,'ENCRYPTION_POSSESSION_MISMATCH'); }
  catch { throw new ContractError('ENCRYPTION_POSSESSION_MISMATCH'); }
  try {
    const p=decode('challenge-plaintext',plaintext);
    check(same(p.context,challenge.context)&&digest('challenge-plaintext',plaintext)===challenge.challenge_digest,'CHALLENGE_CONTEXT_MISMATCH');
    const c=challenge.context;
    return signStateRecord('possession',wire({...common('device-possession-proof'),service_id:c.service_id,account_id:c.account_id,root_fingerprint:c.root_fingerprint,
      challenge_digest:digest('challenge',challengeBytes),device_id:c.device.device_id,session_binding:c.session_binding,challenge_response:p.secret}),signingPrivateKey);
  } finally { sodium.memzero(plaintext); }
}
