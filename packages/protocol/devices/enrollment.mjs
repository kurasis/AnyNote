import {sodium,Buffer} from '../adapters/primitives.mjs';
import { ContractError, requireCondition as check } from '../src/strict-json.mjs';
import { wire, same, decodeIdentity } from '../adapters/codecs/identity-codec.mjs';
import { certificateDetails, signCertificate } from './proofs.mjs';
import { stateDecode as decode, stateDigest as digest, stateCommon as common } from '../adapters/codecs/state-codec.mjs';
import { rosterScope, rosterDetails, certificateBodyForState, activeCertificateForEvaluation,
  signStateRecord, verifyPairingTranscript, verifyEnrollmentApproval, revokedDescendants, rosterEventBody } from './roster.mjs';
import {possession} from '../auth-client.mjs';
const answerPossessionChallenge=(bytes,encryption,signing)=>{const c=decode('challenge',bytes);return wire(possession(c,{signing:{privateKey:signing,publicKey:sodium.crypto_sign_ed25519_sk_to_pk(signing)},encryption:{privateKey:encryption,publicKey:sodium.crypto_scalarmult_base(encryption)}},c.context));};
await sodium.ready;
const b64=b=>Buffer.from(b).toString('base64url'), un64=s=>Buffer.from(s,'base64url');
export const randomOperationId=()=>b64(sodium.randombytes_buf(16));
export function invitationForEvaluation(roster,approverId,operationId,expiresAt,signingKey) {
  const r=rosterDetails(roster),cert=certificateDetails(activeCertificateForEvaluation(roster,approverId,'delegate-device'));
  return signStateRecord('invitation',wire({...common('pairing-invitation'),...rosterScope(roster),operation_id:operationId,
    generation:r.generation,roster:r.head,approver:{device_id:approverId,certificate_digest:cert.digest},nonce:b64(sodium.randombytes_buf(32)),expires_at:expiresAt}),signingKey);
}
export function offerForEvaluation(roster,deviceBytes,sessionBinding,operationId,expiresAt,signingKey,invitationBytes=null) {
  const r=rosterDetails(roster);check(r.head,'ACCOUNT_NOT_REGISTERED');
  return signStateRecord('offer',wire({...common('pairing-offer'),...rosterScope(roster),operation_id:operationId,
    generation:r.generation,roster:r.head,session_binding:sessionBinding,device:decode('device',deviceBytes),nonce:b64(sodium.randombytes_buf(32)),expires_at:expiresAt,
    invitation_digest:invitationBytes?digest('invitation',invitationBytes):null}),signingKey);
}
export function responseForEvaluation(roster,offerBytes,approverId,signingKey,invitationBytes=null,now=null) {
  const offer=decode('offer',offerBytes),r=rosterDetails(roster),cert=certificateDetails(activeCertificateForEvaluation(roster,approverId,'delegate-device'));
  const response=signStateRecord('response',wire({...common('pairing-response'),...rosterScope(roster),operation_id:offer.body.operation_id,
    generation:r.generation,roster:r.head,approver:{device_id:approverId,certificate_digest:cert.digest},offer_digest:digest('offer',offerBytes),
    invitation_digest:offer.body.invitation_digest,nonce:b64(sodium.randombytes_buf(32)),expires_at:offer.body.expires_at}),signingKey);
  const transcript=wire({...common('pairing-transcript'),invitation:invitationBytes?decode('invitation',invitationBytes):null,offer,response:decode('response',response)});
  verifyPairingTranscript(roster,transcript,now);
  return {response,transcript};
}
export function approvalForEvaluation(roster,transcriptBytes,approverPrivateKey,now) {
  const v=verifyPairingTranscript(roster,transcriptBytes,now),r=rosterDetails(roster),device=v.offer.device;
  const certificate=signCertificate(certificateBodyForState(roster,wire(device),r.generation,r.head,
    {kind:'device',device_id:v.actor.cert.body.device_id,certificate_digest:v.actor.cert.digest},v.transcript_digest),approverPrivateKey);
  const secret=sodium.randombytes_buf(32),plain=wire({purpose:'pairing-encryption-proof',transcript_digest:v.transcript_digest,device_id:device.device_id,secret:b64(secret)});
  try {
    const approval=signStateRecord('approval',wire({...common('enrollment-approval'),...rosterScope(roster),operation_id:v.offer.operation_id,
      generation:r.generation,roster:r.head,session_binding:v.offer.session_binding,transcript_digest:v.transcript_digest,
      certificate:decodeIdentity('certificate',certificate),sealed_challenge:b64(sodium.crypto_box_seal(plain,un64(device.encryption_key))),
      challenge_digest:digest('pairing-proof-plaintext',plain),expires_at:v.offer.expires_at}),approverPrivateKey);
    verifyEnrollmentApproval(roster,transcriptBytes,approval,now);return approval;
  } finally { sodium.memzero(secret);sodium.memzero(plain); }
}
export function confirmationForEvaluation(roster,transcriptBytes,approvalBytes,encryptionPrivateKey,signingPrivateKey,now) {
  const v=verifyEnrollmentApproval(roster,transcriptBytes,approvalBytes,now),a=v.approval.body;let plain;
  try { plain=sodium.crypto_box_seal_open(un64(a.sealed_challenge),un64(v.device.encryption_key),encryptionPrivateKey); check(plain,'ENCRYPTION_POSSESSION_MISMATCH'); }
  catch { throw new ContractError('ENCRYPTION_POSSESSION_MISMATCH'); }
  try {
    const inner=decode('pairing-proof-plaintext',plain);
    check(inner.transcript_digest===v.transcript_digest&&inner.device_id===v.device.device_id&&digest('pairing-proof-plaintext',plain)===a.challenge_digest,'ENCRYPTION_POSSESSION_MISMATCH');
    return signStateRecord('confirmation',wire({...common('enrollment-confirmation'),...rosterScope(roster),operation_id:v.offer.operation_id,
      generation:a.generation,roster:a.roster,session_binding:a.session_binding,transcript_digest:v.transcript_digest,
      certificate_digest:certificateDetails(v.proof).digest,approval_digest:digest('approval',approvalBytes),challenge_response:inner.secret}),signingPrivateKey);
  } finally { sodium.memzero(plain); }
}
export function enrollmentEventForEvaluation(roster,transcriptBytes,approvalBytes,confirmationBytes,newDevicePrivateKey) {
  const transcript=decode('transcript',transcriptBytes),approval=decode('approval',approvalBytes),confirmation=decode('confirmation',confirmationBytes);
  return signStateRecord('event',rosterEventBody(roster,'enroll',transcript.offer.body.operation_id,transcript.offer.body.device.device_id,{transcript,approval,confirmation}),newDevicePrivateKey);
}
export function rootEventForEvaluation(roster,challengeBytes,deviceKeys,rootPrivateKey,activeDeviceLimit='5',operationId=randomOperationId()) {
  const challenge=decode('challenge',challengeBytes),r=rosterDetails(roster),kind=challenge.context.intent;
  check(['register','reset'].includes(kind),'UNSUPPORTED_PURPOSE');
  const certificate=signCertificate(certificateBodyForState(roster,wire(challenge.context.device),kind==='reset'?String(BigInt(r.generation)+1n):'0',r.head,
    {kind:'root',root_fingerprint:rosterScope(roster).root_fingerprint},digest('challenge',challengeBytes)),rootPrivateKey);
  const confirmation=answerPossessionChallenge(challengeBytes,deviceKeys.encryption.privateKey,deviceKeys.signing.privateKey);
  return signStateRecord('event',rosterEventBody(roster,kind,operationId,'root',{challenge,certificate:decodeIdentity('certificate',certificate),confirmation:decode('possession',confirmation),active_device_limit:activeDeviceLimit}),rootPrivateKey);
}
export function revokeEventForEvaluation(roster,actorId,targets,privateKey,operationId=randomOperationId()) {
  const ordered=[...targets].sort(),affected=revokedDescendants(roster,ordered);
  return signStateRecord('event',rosterEventBody(roster,'revoke',operationId,actorId,{targets:ordered,affected_devices:affected}),privateKey);
}
