// Pinned signed-chain evaluator only. Group roles/history and durable server
// authentication/transactions are separate mandatory layers, never implied.
import sodium from 'libsodium-wrappers-sumo';
import { requireCondition as check } from './strict-json.mjs';
import { wire, same, decodeIdentity } from './identity-codec.mjs';
import { identityDetails, certificateDetails, verifyCertificateSignature,
  recipientForDevice, recipientForRecovery, senderForCertificate,
  verifyDistributionSignature, openGroupKeyForEvaluation } from './identity-crypto.mjs';
import { stateDecode as decode, stateEncode as encode, stateSigningInput as signing,
  stateDigest as digest, stateCommon as common } from './state-codec.mjs';
await sodium.ready;
const states = new WeakMap(), b64 = b => Buffer.from(b).toString('base64url'), un64 = s => Buffer.from(s, 'base64url');
export function signStateRecord(kind, bodyBytes, privateKey) {
  check(privateKey instanceof Uint8Array && privateKey.length === 64, 'INVALID_KEY_LENGTH');
  const body = decode(`${kind}-body`, bodyBytes);
  return encode(kind, wire({ body, signature: b64(sodium.crypto_sign_detached(signing(`${kind}-body`, wire(body)), privateKey)) }));
}
export function verifyStateRecord(kind, record, publicKey) {
  check(sodium.crypto_sign_verify_detached(un64(record.signature), signing(`${kind}-body`, wire(record.body)), un64(publicKey)), 'SIGNATURE_INVALID');
}
export function newRosterForEvaluation(identityProof) {
  const identity = identityDetails(identityProof);
  const token = Object.freeze({ scope: 'PINNED_ROSTER_EVALUATION', group_authorization: 'NOT_EVALUATED' });
  states.set(token, { identityProof, identity, head: null, generation: '0', deviceLimit: null,
    devices: new Map(), operations: new Set(), events: [], pending: new Map(), terminalPending: new Set(), retiredPendingDevices: new Map(), retiredPendingBindings: new Set() });
  return token;
}
function state(token) { check(states.has(token), 'ROSTER_PROOF_REQUIRED'); return states.get(token); }
export function rosterScope(token) {
  const s = state(token); return { service_id: s.identity.body.service_id, account_id: s.identity.body.account_id, root_fingerprint: s.identity.fingerprint };
}
function scopeMatch(s, value) {
  check(value.service_id === s.identity.body.service_id && value.account_id === s.identity.body.account_id && value.root_fingerprint === s.identity.fingerprint, 'ROSTER_CONTEXT_MISMATCH');
}
export function activeCertificateForEvaluation(token, deviceId, capability) {
  const s = state(token), device = s.devices.get(deviceId);
  check(device && device.status === 'ACTIVE' && device.generation === s.generation, 'DEVICE_NOT_ACTIVE');
  if (capability) check(certificateDetails(device.proof).body.capabilities.includes(capability), 'CAPABILITY_MISMATCH');
  return device.proof;
}
export function historicalCertificateForEvaluation(token, deviceId) {
  const device = state(token).devices.get(deviceId); check(device, 'UNKNOWN_DEVICE');
  // A historical certificate is NOT a historical content/writer acceptance.
  return device.proof;
}
export function rosterDetails(token) {
  const s = state(token);
  return { scope: rosterScope(token), head: structuredClone(s.head), generation: s.generation,
    active_device_limit: s.deviceLimit, devices: [...s.devices].map(([device_id,d]) => ({ device_id, status:d.status, generation:d.generation, parent_device_id:d.parent,
      certificate_digest:certificateDetails(d.proof).digest })), pending_operations:[...s.pending.keys()].sort(),
    event_count:s.events.length, device_roster_authorization:'VERIFIED_FROM_PINNED_CHAIN', group_authorization:'NOT_EVALUATED' };
}
export const rosterEvents = token => state(token).events.map(bytes => Buffer.from(bytes));
export function certificateBodyForState(token, deviceBytes, generation, predecessor, issuer, transcriptDigest) {
  const device = decode('device', deviceBytes);
  return wire({ purpose:'provisional-device-certificate', contract:'p02-identity-c1', protocol:'anynote', protocol_version:1,
    ...rosterScope(token), recovery_generation:generation, predecessor_roster:predecessor, issuer,
    device_id:device.device_id, device_signing_key:device.signing_key, device_encryption_key:device.encryption_key,
    capabilities:device.capabilities, pairing_transcript_digest:transcriptDigest });
}
function freshDevice(s, device) {
  check(!s.devices.has(device.device_id) && !s.retiredPendingDevices.has(device.device_id), 'DEVICE_ID_REUSE');
  for (const prior of s.retiredPendingDevices.values()) check(![prior.signing_key,prior.encryption_key].includes(device.signing_key) && ![prior.signing_key,prior.encryption_key].includes(device.encryption_key), 'DEVICE_KEY_REUSE');
  for (const prior of s.devices.values()) {
    const keys = certificateDetails(prior.proof).body;
    check(device.signing_key !== keys.device_signing_key && device.encryption_key !== keys.device_encryption_key &&
      device.signing_key !== keys.device_encryption_key && device.encryption_key !== keys.device_signing_key, 'DEVICE_KEY_REUSE');
  }
}
export function pairingWindow(expiresAt, now) {
  check(typeof now === 'bigint' && now >= 0n && now <= 9223372036854775807n, 'INVALID_CLOCK');
  check(BigInt(expiresAt) > now && BigInt(expiresAt) - now <= 600000n, 'PAIRING_EXPIRED_OR_OUT_OF_RANGE');
}
function actorFor(s, token, actor, capability) {
  const proof = activeCertificateForEvaluation(token, actor.device_id, capability), cert = certificateDetails(proof);
  check(cert.digest === actor.certificate_digest, 'ISSUER_CONTEXT_MISMATCH');
  return { proof, cert };
}
export function verifyPairingTranscript(token, transcriptBytes, now = null) {
  const s = state(token), t = decode('transcript', transcriptBytes), offer = t.offer.body, response = t.response.body;
  check(s.head, 'ACCOUNT_NOT_REGISTERED');
  for (const body of [offer, response]) { scopeMatch(s, body); check(body.generation === s.generation && same(body.roster,s.head), 'ROSTER_CHANGED'); }
  decode('device', wire(offer.device)); freshDevice(s, offer.device);
  check(!s.retiredPendingBindings.has(offer.session_binding),'ENROLLMENT_SESSION_REUSE');
  verifyStateRecord('offer', t.offer, offer.device.signing_key);
  check(response.operation_id === offer.operation_id && response.offer_digest === digest('offer',wire(t.offer)) &&
    response.invitation_digest === offer.invitation_digest && response.expires_at === offer.expires_at, 'PAIRING_TRANSCRIPT_MISMATCH');
  const actor = actorFor(s,token,response.approver,'delegate-device');
  verifyStateRecord('response',t.response,actor.cert.body.device_signing_key);
  if (t.invitation) {
    const invite = t.invitation.body; scopeMatch(s,invite);
    check(invite.generation === s.generation && same(invite.roster,s.head) && same(invite.approver,response.approver) &&
      invite.operation_id === offer.operation_id && invite.expires_at === offer.expires_at &&
      digest('invitation',wire(t.invitation)) === offer.invitation_digest, 'PAIRING_TRANSCRIPT_MISMATCH');
    verifyStateRecord('invitation',t.invitation,actor.cert.body.device_signing_key);
  } else check(offer.invitation_digest === null, 'PAIRING_TRANSCRIPT_MISMATCH');
  if (now !== null) pairingWindow(offer.expires_at,now);
  return { transcript:t, offer, actor, transcript_digest:digest('transcript',transcriptBytes) };
}
export function verifyEnrollmentApproval(token, transcriptBytes, approvalBytes, now = null) {
  const s = state(token), verified = verifyPairingTranscript(token,transcriptBytes,now), approval = decode('approval',approvalBytes), a = approval.body;
  scopeMatch(s,a);
  check(a.operation_id === verified.offer.operation_id && a.generation === s.generation && same(a.roster,s.head) &&
    a.session_binding === verified.offer.session_binding && a.transcript_digest === verified.transcript_digest && a.expires_at === verified.offer.expires_at, 'APPROVAL_CONTEXT_MISMATCH');
  verifyStateRecord('approval',approval,verified.actor.cert.body.device_signing_key);
  const device = decode('device',wire(verified.offer.device));
  check(device.capabilities.every(cap => verified.actor.cert.body.capabilities.includes(cap)), 'CAPABILITY_ESCALATION');
  const expected = certificateBodyForState(token,wire(device),s.generation,s.head,
    {kind:'device',device_id:verified.actor.cert.body.device_id,certificate_digest:verified.actor.cert.digest},verified.transcript_digest);
  const proof = verifyCertificateSignature(wire(a.certificate),s.identityProof,expected,verified.actor.proof);
  return { ...verified, approval, proof, device };
}
export function stageEnrollmentForEvaluation(token, transcriptBytes, approvalBytes, now) {
  const s = state(token), v = verifyEnrollmentApproval(token,transcriptBytes,approvalBytes,now), op = v.offer.operation_id;
  expirePendingEnrollmentsForEvaluation(token,now);
  freshDevice(s,v.device);check(!s.retiredPendingBindings.has(v.offer.session_binding),'ENROLLMENT_SESSION_REUSE');
  check(!s.operations.has(op) && !s.pending.has(op) && !s.terminalPending.has(op), 'OPERATION_REPLAY');
  check(s.terminalPending.size<4096,'RESOURCE_LIMIT');
  check(s.pending.size < 32, 'RESOURCE_LIMIT');
  check([...s.devices.values()].filter(d => d.status === 'ACTIVE').length < Number(s.deviceLimit), 'DEVICE_LIMIT');
  s.pending.set(op,{transcript:Buffer.from(transcriptBytes),approval:Buffer.from(approvalBytes)});
  return { state:'APPROVED', device_active:false, session_upgrade:false, group_key_release:false };
}
export function pendingEnrollmentForEvaluation(token, operationId) {
  const value = state(token).pending.get(operationId); check(value,'PENDING_APPROVAL_REQUIRED');
  return {transcript:Buffer.from(value.transcript),approval:Buffer.from(value.approval)};
}
export function revokedDescendants(token, targets) {
  const s = state(token); decode('revoke-payload',wire({targets,affected_devices:targets}));
  const affected = new Set(targets);
  for (const target of targets) activeCertificateForEvaluation(token,target);
  let changed=true;
  while(changed) { changed=false; for(const [id,d] of s.devices) if(d.status==='ACTIVE' && affected.has(d.parent) && !affected.has(id)) { affected.add(id);changed=true; } }
  return [...affected].sort();
}
function verifyPossession(token, challenge, confirmation) {
  const s=state(token), context=challenge.context; scopeMatch(s,context);
  decode('device',wire(context.device));
  const body=confirmation.body; scopeMatch(s,body);
  check(body.challenge_digest===digest('challenge',wire(challenge)) && body.device_id===context.device.device_id && body.session_binding===context.session_binding,'POSSESSION_CONTEXT_MISMATCH');
  verifyStateRecord('possession',confirmation,context.device.signing_key);
  const plaintext={purpose:'device-encryption-proof',context,secret:body.challenge_response};
  check(digest('challenge-plaintext',wire(plaintext))===challenge.challenge_digest,'ENCRYPTION_POSSESSION_MISMATCH');
}
export function verifyDevicePossessionForEvaluation(token, challengeBytes, confirmationBytes) {
  const challenge=decode('challenge',challengeBytes), confirmation=decode('possession',confirmationBytes);
  verifyPossession(token,challenge,confirmation);
  return {device_id:challenge.context.device.device_id,session_binding:challenge.context.session_binding};
}
export function applyRosterEventForEvaluation(token, eventBytes, now = null) {
  const s = state(token), event = decode('event',eventBytes), b=event.body;
  scopeMatch(s,b);
  check(s.events.length<1000,'RESOURCE_LIMIT');
  check(!s.operations.has(b.operation_id),'OPERATION_REPLAY');
  check(same(b.predecessor,s.head) && b.version === (s.head ? String(BigInt(s.head.version)+1n) : '0'),'ROSTER_CHANGED');
  let activated=null, parent=null, revoked=[];
  let nextGeneration=s.generation, nextLimit=s.deviceLimit;
  if(b.kind==='register'||b.kind==='reset') {
    check((b.kind==='register')===!s.head,'INVALID_ROOT_TRANSITION');
    nextGeneration=b.kind==='reset'?String(BigInt(s.generation)+1n):'0';
    check(b.generation===nextGeneration,'GENERATION_MISMATCH');
    const {challenge,certificate,confirmation,active_device_limit:limit}=b.payload, c=challenge.context;
    scopeMatch(s,c);
    check(c.intent===b.kind && c.generation===s.generation && same(c.roster,s.head),'CHALLENGE_CONTEXT_MISMATCH');
    check(BigInt(limit)>=1n && BigInt(limit)<=32n && (s.deviceLimit===null || limit===s.deviceLimit),'DEVICE_LIMIT_POLICY_MISMATCH');
    nextLimit=limit;
    if(now!==null) { pairingWindow(c.expires_at,now);check(BigInt(c.expires_at)-now<=60000n,'CHALLENGE_EXPIRED_OR_OUT_OF_RANGE'); }
    freshDevice(s,c.device);verifyPossession(token,challenge,confirmation);
    const expected=certificateBodyForState(token,wire(c.device),nextGeneration,s.head,{kind:'root',root_fingerprint:s.identity.fingerprint},digest('challenge',wire(challenge)));
    activated=verifyCertificateSignature(wire(certificate),s.identityProof,expected);
    verifyStateRecord('event',event,s.identity.body.root_signing_key);
    if(b.kind==='reset') revoked=[...s.devices].filter(([,d])=>d.status==='ACTIVE').map(([id])=>id).sort();
  } else {
    check(s.head && b.generation===s.generation,'GENERATION_MISMATCH');
    if(b.kind==='enroll') {
      const {transcript,approval,confirmation}=b.payload, v=verifyEnrollmentApproval(token,wire(transcript),wire(approval),now), c=confirmation.body;
      scopeMatch(s,c);
      const cert=certificateDetails(v.proof);
      check(c.operation_id===b.operation_id && c.operation_id===v.offer.operation_id && c.generation===s.generation && same(c.roster,s.head) &&
        c.session_binding===v.offer.session_binding && c.transcript_digest===v.transcript_digest && c.certificate_digest===cert.digest && c.approval_digest===digest('approval',wire(approval)),'CONFIRMATION_CONTEXT_MISMATCH');
      verifyStateRecord('confirmation',confirmation,v.device.signing_key);
      check(digest('pairing-proof-plaintext',wire({purpose:'pairing-encryption-proof',transcript_digest:v.transcript_digest,device_id:v.device.device_id,secret:c.challenge_response}))===approval.body.challenge_digest,'ENCRYPTION_POSSESSION_MISMATCH');
      check(b.signer===v.device.device_id,'EVENT_SIGNER_MISMATCH');verifyStateRecord('event',event,v.device.signing_key);
      check([...s.devices.values()].filter(d=>d.status==='ACTIVE').length<Number(s.deviceLimit),'DEVICE_LIMIT');
      activated=v.proof;parent=v.actor.cert.body.device_id;
    } else {
      const actor=certificateDetails(activeCertificateForEvaluation(token,b.signer,'delegate-device'));
      decode('revoke-payload',wire(b.payload));
      revoked=revokedDescendants(token,b.payload.targets);
      check(same(revoked,b.payload.affected_devices),'DESCENDANT_CLOSURE_MISMATCH');
      check(!revoked.includes(b.signer),'REVOKER_IN_CLOSURE');
      verifyStateRecord('event',event,actor.body.device_signing_key);
    }
  }
  // Build/validate everything before the sole mutation block. No DB/server I/O.
  const newHead={version:b.version,digest:digest('event',eventBytes)};
  for(const id of revoked) s.devices.get(id).status='REVOKED';
  if(activated) { const cert=certificateDetails(activated);s.devices.set(cert.body.device_id,{status:'ACTIVE',generation:nextGeneration,parent,proof:activated}); }
  s.generation=nextGeneration;s.deviceLimit=nextLimit;s.head=newHead;s.operations.add(b.operation_id);s.events.push(Buffer.from(eventBytes));for(const op of s.pending.keys())retirePending(s,op);s.pending.clear();
  return { head:structuredClone(newHead), generation:nextGeneration, activated_device_id:activated?certificateDetails(activated).body.device_id:null,
    revoked_device_ids:revoked, pending_invalidated:true, groups_require_maintenance:revoked.length>0,
    durable_transaction:'NOT_IMPLEMENTED',group_authorization:'NOT_EVALUATED' };
}
export function replayRosterForEvaluation(identityProof, eventInputs, pinnedHeadBytes) {
  check(Array.isArray(eventInputs)&&eventInputs.length>0&&eventInputs.length<=1000,'RESOURCE_LIMIT');
  check(eventInputs.reduce((sum,b)=>sum+b.length,0)<=16_777_216,'RESOURCE_LIMIT');
  const token=newRosterForEvaluation(identityProof);
  for(const bytes of eventInputs) applyRosterEventForEvaluation(token,bytes);
  // Pinned head is independent OOB/local evidence, never taken from the same log.
  const expected=decode('head',pinnedHeadBytes);
  check(same(state(token).head,expected),'ROSTER_PIN_MISMATCH');
  return token;
}
export function activeRecipientForRosterEvaluation(token, deviceId) {
  const s=state(token);return recipientForDevice(activeCertificateForEvaluation(token,deviceId,'receive-group-key'),s.head);
}
export function recoveryRecipientForRosterEvaluation(token) {
  const s=state(token);check(s.head,'ACCOUNT_NOT_REGISTERED');return recipientForRecovery(s.identityProof,s.generation,s.head);
}
export function checkGrantRostersForEvaluation(recordBytes, expectedContextBytes, issuerToken, recipientToken) {
  const record=decodeIdentity('grant',recordBytes);
  const issuerState=state(issuerToken), recipientState=state(recipientToken), ctx=record.body?.context;
  check(ctx?.issuer && ctx?.recipient,'SCHEMA_MISMATCH');
  const issuer=activeCertificateForEvaluation(issuerToken,ctx.issuer.device_id,'distribute-group-key');
  check(same(ctx.issuer,senderForCertificate(issuer,issuerState.head)),'ROSTER_CHANGED');
  const expected=ctx.recipient.kind==='device'?activeRecipientForRosterEvaluation(recipientToken,ctx.recipient.device_id):recoveryRecipientForRosterEvaluation(recipientToken);
  check(same(ctx.recipient,expected) && ctx.service_id===rosterScope(recipientToken).service_id,'ROSTER_CHANGED');
  const result=verifyDistributionSignature(recordBytes,expectedContextBytes,issuer);
  return { ...result, device_roster_authorization:'VERIFIED_FROM_PINNED_CHAIN', group_authorization:'NOT_EVALUATED' };
}
export function openGroupKeyWithRostersForEvaluation(recordBytes, expectedContextBytes, issuerToken, recipientToken, publicKey, privateKey) {
  const result=checkGrantRostersForEvaluation(recordBytes,expectedContextBytes,issuerToken,recipientToken);
  const proof=activeCertificateForEvaluation(issuerToken,result.record.body.context.issuer.device_id,'distribute-group-key');
  return openGroupKeyForEvaluation(recordBytes,expectedContextBytes,proof,publicKey,privateKey);
}

export function rosterEventBody(token, kind, operationId, signer, payload) {
  const s=state(token);
  return encode('event-body',wire({...common('device-roster-event'),...rosterScope(token),kind,operation_id:operationId,
    generation:kind==='reset'?String(BigInt(s.generation)+1n):s.generation,
    version:s.head?String(BigInt(s.head.version)+1n):'0',predecessor:s.head,signer,payload}));
}

function retirePending(s,op) {
  const pending=s.pending.get(op),offer=decode('transcript',pending.transcript).offer.body;
  s.terminalPending.add(op);s.retiredPendingDevices.set(offer.device.device_id,offer.device);s.retiredPendingBindings.add(offer.session_binding);
}
export function expirePendingEnrollmentsForEvaluation(token,now) {
  const s=state(token);check(typeof now==='bigint'&&now>=0n,'INVALID_CLOCK');const expired=[];
  for(const [op,p] of s.pending) if(BigInt(decode('approval',p.approval).body.expires_at)<=now) {retirePending(s,op);s.pending.delete(op);expired.push(op);}
  return expired.sort();
}
export function cancelPendingEnrollmentForEvaluation(token,operationId) {
  const s=state(token);check(s.pending.has(operationId),'PENDING_APPROVAL_REQUIRED');retirePending(s,operationId);s.pending.delete(operationId);
  return {state:'CANCELLED',device_active:false,group_key_release:false};
}
