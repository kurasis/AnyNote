// Authentication transport and initial PUBLIC root bootstrap. Persistent custody belongs to P07.
import Ajv2020 from 'ajv/dist/2020.js';
import schemas from '../contracts/generated/runtime-schemas.json' with {type:'json'};
import {strictJson} from './src/strict-json.mjs';
import {sodium, Buffer, b64, un64, hash, randomKey, deviceKeys} from './adapters/primitives.mjs';
import {createIdentity, deriveRoot, encodeRecoverySecret} from './adapters/identity.mjs';
import {identityDigest, wire, same} from './adapters/codecs/identity-codec.mjs';
import {stateDigest, stateDecode} from './adapters/codecs/state-codec.mjs';
import {formats} from './auth-formats.mjs';
import {decode as decodeProtocol} from './adapters/codecs/protocol-codec.mjs';
const ajv = new Ajv2020({strict:true,ownProperties:true});
for (const [name, check] of Object.entries(formats)) ajv.addFormat(name,check);
for (const s of schemas) ajv.addSchema(s);
const validators=new Map(Object.keys(schemas.find(s=>s.$id==='urn:anynote:p06:auth:v1').$defs).map(k=>[k,ajv.compile({$ref:'urn:anynote:p06:auth:v1#/$defs/'+k})]));
const capabilityValidator=ajv.compile({$ref:'urn:anynote:p03:api-foundation:v1#/$defs/capabilities'});
export function authCapabilities(bytes){
  const v=strictJson(bytes,4096);
  if(!capabilityValidator(v))throw Error('INVALID_CAPABILITIES');
  decodeProtocol('negotiation',Buffer.from(JSON.stringify(v.negotiation)));
  if(!v.features.account_authentication)throw Error('AUTHENTICATION_UNAVAILABLE');
  return v;
}
export async function boundedResponse(response,maximum=262144){
  const size=response.headers.get('Content-Length');
  if(size&&(!/^[0-9]+$/.test(size)||BigInt(size)>BigInt(maximum))){await response.body?.cancel();throw Error('AUTH_RESPONSE_TOO_LARGE');}
  if(!response.body)throw Error('EMPTY_AUTH_RESPONSE');
  const reader=response.body.getReader(),parts=[];let length=0;
  try{while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>maximum)throw Error('AUTH_RESPONSE_TOO_LARGE');parts.push(value);}return Buffer.concat(parts);}
  finally{await reader.cancel();reader.releaseLock();}
}
export function authValue(kind, value) {
  if (!validators.get(kind)?.(value)) throw Error('INVALID_AUTH_DTO');
  return value;
}
export function authBytes(kind, bytes) { return authValue(kind,strictJson(bytes,262144)); }
export class AuthClient {
  #csrf;
  #csrfPromise;
  constructor(issuer, fetcher=globalThis.fetch) {
    const url=new URL(issuer);
    if(url.protocol!=='https:'||url.origin!==issuer||url.username||url.password) throw Error('INVALID_ISSUER');
    this.issuer=issuer;this.fetcher=fetcher;
  }
  async call(path, requestKind, responseKind, body, method=requestKind?'POST':'GET') {
    if(!/^\/(?:auth|accounts|me)(?:\/[A-Za-z0-9_-]+)*$/.test(path)) throw Error('INVALID_AUTH_PATH');
    if(requestKind) authValue(requestKind,body);
    if(requestKind&&!this.#csrf) await this.csrf();
    const response=await this.fetcher(this.issuer+'/api/v1'+path,{method,credentials:'include',cache:'no-store',redirect:'error',headers:{Accept:'application/json',...(requestKind?{'Content-Type':'application/json','X-CSRF-TOKEN':this.#csrf}:{})},...(requestKind?{body:JSON.stringify(body)}:{})});
    const bytes=await boundedResponse(response,response.ok?262144:4096);
    if(!response.ok){this.#csrf=undefined;const e=strictJson(bytes,4096);throw Error(e.error?.code??'AUTH_DENIED');}
    const result=authBytes(responseKind,bytes);
    if(result.csrf_token) this.#csrf=result.csrf_token;
    return result;
  }
  csrf(){return this.#csrfPromise??=this.call('/auth/csrf',null,'csrf-result').finally(()=>{this.#csrfPromise=undefined;});}
  async ceremony(ceremony, extra={}) {
    const o=await this.call('/auth/passkeys/options','options-request','options-result',{version:1,ceremony,...extra});
    const p=structuredClone(o.publicKey);p.challenge=un64(p.challenge);
    // Maintained PHP serialization uses null for absent attachment; WebIDL requires omission.
    if(p.authenticatorSelection?.authenticatorAttachment===null)delete p.authenticatorSelection.authenticatorAttachment;
    if(p.user)p.user.id=un64(p.user.id);
    for(const d of [...(p.allowCredentials??[]),...(p.excludeCredentials??[])])d.id=un64(d.id);
    const c=await navigator.credentials[ceremony==='register'||ceremony==='add'?'create':'get']({publicKey:p});
    if(!c)throw Error('PASSKEY_CANCELLED');
    const r=c.response;
    const response={clientDataJSON:b64(new Uint8Array(r.clientDataJSON)),...(r.attestationObject?{attestationObject:b64(new Uint8Array(r.attestationObject)),transports:r.getTransports?.()??[]}:{authenticatorData:b64(new Uint8Array(r.authenticatorData)),signature:b64(new Uint8Array(r.signature)),userHandle:r.userHandle===null?null:b64(new Uint8Array(r.userHandle))})};
    const credential={id:c.id,rawId:b64(new Uint8Array(c.rawId)),type:'public-key',response};
    const verified=await this.call('/auth/passkeys/verify','verify-request','verify-result',{version:1,challenge_id:o.challenge_id,credential});
    return {...verified};
  }
}
// Human-readable outer export keeps the frozen P02 kit unchanged. URL is a hint,
// never authority for recovery connections; import must use independent service pins.
export function recoveryKitExport(issuer,kit){
  const u=new URL(issuer);
  if(u.protocol!=='https:'||u.origin!==issuer||u.username||u.password)throw Error('INVALID_ISSUER');
  return authValue('recovery-kit-export',{version:1,service_url:issuer,instructions:'Keep this file offline and private. Its checksummed recovery secret restores the account root; authentication recovery codes restore sign-in only. Use your independently trusted service address and verify the service ID, account ID and root fingerprint before recovery. Never send the recovery secret to the API.',kit});
}
export function deviceCommitment(device){return hash(Buffer.concat([Buffer.from('AnyNote/P06/device-key-commitment\0'),un64(device.signing_key),un64(device.encryption_key)]));}
const stateCommon={contract:'p02-state-c1',protocol:'anynote',protocol_version:1};
const identityCommon={contract:'p02-identity-c1',protocol:'anynote',protocol_version:1};
// All secrets live only in memory. Explicit small recovery-kit export is the sole durable output.
export async function initialRoot(service,account) {
  const secret=randomKey(),keys=deviceKeys(),context={...identityCommon,purpose:'account-root-derivation',service_id:service,account_id:account};
  let root;
  try {
    const identity=JSON.parse(Buffer.from(await createIdentity(secret,wire(context))).toString());
    root=await deriveRoot(secret,wire(context));
    const fingerprint=identityDigest('identity-body',wire(identity.body));
    const device={device_id:b64(sodium.randombytes_buf(16)),signing_key:b64(keys.signing.publicKey),encryption_key:b64(keys.encryption.publicKey),capabilities:['delegate-device','distribute-group-key','receive-group-key','sign-content']};
    const kit={purpose:'account-recovery-kit',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,service_id:service,account_id:account,root_fingerprint:fingerprint,identity,recovery_secret:encodeRecoverySecret(secret)};
    return {identity,device,keys,root,fingerprint,kit,dispose(){sodium.memzero(keys.signing.privateKey);sodium.memzero(keys.encryption.privateKey);sodium.memzero(root.signing.privateKey);sodium.memzero(root.recovery.privateKey);kit.recovery_secret='';}};
  }catch(e){sodium.memzero(keys.signing.privateKey);sodium.memzero(keys.encryption.privateKey);if(root){sodium.memzero(root.signing.privateKey);sodium.memzero(root.recovery.privateKey);}throw e;}
  finally{sodium.memzero(secret);}
}
export function possession(challenge, keys, expected) {
  const c=stateDecode('challenge',wire(challenge));
  for(const field of ['service_id','account_id','root_fingerprint'])if(c.context[field]!==expected[field])throw Error('CHALLENGE_CONTEXT_MISMATCH');
  if(c.context.device.signing_key!==b64(keys.signing.publicKey)||c.context.device.encryption_key!==b64(keys.encryption.publicKey)||BigInt(c.context.expires_at)<=BigInt(Date.now())||BigInt(c.context.expires_at)>BigInt(Date.now()+125000))throw Error('CHALLENGE_CONTEXT_MISMATCH');
  if(expected.session_id&&c.context.session_binding!==hash(Buffer.from('AnyNote/P06/session-binding\0'+expected.session_id)))throw Error('SESSION_BINDING_MISMATCH');
  const bytes=sodium.crypto_box_seal_open(un64(c.sealed_challenge),keys.encryption.publicKey,keys.encryption.privateKey);
  try {
    const plain=stateDecode('challenge-plaintext',bytes);
    if(!same(plain.context,c.context))throw Error('INNER_CONTEXT_MISMATCH');
    if(stateDigest('challenge-plaintext',bytes)!==c.challenge_digest)throw Error('INNER_CONTEXT_MISMATCH');
    const body={...stateCommon,purpose:'device-possession-proof',service_id:c.context.service_id,account_id:c.context.account_id,root_fingerprint:c.context.root_fingerprint,challenge_digest:stateDigest('challenge',wire(c)),device_id:c.context.device.device_id,session_binding:c.context.session_binding,challenge_response:plain.secret};
    const raw=stateDecode('possession-body',wire(body));
    // Use the frozen domain and maintained JCS implementation.
    const {stateSigningInput}=stateExports;
    return {body:raw,signature:b64(sodium.crypto_sign_detached(stateSigningInput('possession-body',wire(body)),keys.signing.privateKey))};
  }finally{sodium.memzero(bytes);}
}
import * as stateExports from './adapters/codecs/state-codec.mjs';
import {identitySigningInput} from './adapters/codecs/identity-codec.mjs';
export function registrationRequest(registration,initial,challenge) {
  const expected={service_id:initial.identity.body.service_id,account_id:initial.identity.body.account_id,root_fingerprint:initial.fingerprint};
  if(challenge.context.intent!=='register'||challenge.context.generation!=='0'||challenge.context.roster!==null)throw Error('INVALID_REGISTER_CHALLENGE');
  const confirmation=possession(challenge,initial.keys,expected);
  const cb={...identityCommon,purpose:'provisional-device-certificate',...expected,recovery_generation:'0',predecessor_roster:null,issuer:{kind:'root',root_fingerprint:initial.fingerprint},device_id:initial.device.device_id,device_signing_key:initial.device.signing_key,device_encryption_key:initial.device.encryption_key,capabilities:initial.device.capabilities,pairing_transcript_digest:stateDigest('challenge',wire(challenge))};
  const certificate={body:cb,signature:b64(sodium.crypto_sign_detached(identitySigningInput('certificate-body',wire(cb)),initial.root.signing.privateKey))};
  const operation=b64(sodium.randombytes_buf(16));
  const body={...stateCommon,purpose:'device-roster-event',...expected,operation_id:operation,generation:'0',version:'0',predecessor:null,kind:'register',signer:'root',payload:{challenge,certificate,confirmation,active_device_limit:'5'}};
  return authValue('register-request',{version:1,registration_id:registration,operation_id:operation,identity:initial.identity,roster:{body,signature:b64(sodium.crypto_sign_detached(stateExports.stateSigningInput('event-body',wire(body)),initial.root.signing.privateKey))}});
}
