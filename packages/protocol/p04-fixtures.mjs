// Disposable PUBLIC synthetic SQL-test inputs. Never a production enrollment path.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';
import { wire, encodeIdentity, identitySigningInput, identityDigest } from './src/identity-codec.mjs';
import { encryptObjectForEvaluation } from './src/object-crypto.mjs';
import { signingInput, digest } from './src/protocol-codec.mjs';
await sodium.ready;
const b64=b=>Buffer.from(b).toString('base64url');
const id=n=>b64(Buffer.alloc(16,n));
const hash=n=>b64(Buffer.alloc(32,n));
const service=id(0); // Configured only in synthetic test kernels; never a deployment identity.
const sign=(body,key)=>({body,signature:b64(sodium.crypto_sign_detached(identitySigningInput(body.purpose==='account-root-identity'?'identity-body':'certificate-body',wire(body)),key))});
const accounts=[];
for(let i=1;i<=3;i++){
 const root=sodium.crypto_sign_seed_keypair(Buffer.alloc(32,100+i));
 const device=sodium.crypto_sign_seed_keypair(Buffer.alloc(32,i));
 const encryption=sodium.crypto_box_seed_keypair(Buffer.alloc(32,50+i));
 const rootBody={purpose:'account-root-identity',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,derivation:'hkdf-sha256-c1',service_id:service,account_id:id(i),root_signing_key:b64(root.publicKey),recovery_encryption_key:b64(encryption.publicKey)};
 const identity=sign(rootBody,root.privateKey);
 const fingerprint=identityDigest('identity-body',wire(rootBody));
 const certBody={purpose:'provisional-device-certificate',contract:'p02-identity-c1',protocol:'anynote',protocol_version:1,service_id:service,account_id:id(i),root_fingerprint:fingerprint,recovery_generation:'0',predecessor_roster:null,issuer:{kind:'root',root_fingerprint:fingerprint},device_id:id(10+i),device_signing_key:b64(device.publicKey),device_encryption_key:b64(encryption.publicKey),capabilities:['delegate-device','distribute-group-key','receive-group-key','sign-content'],pairing_transcript_digest:hash(i)};
 const certificate=sign(certBody,root.privateKey);
 encodeIdentity('identity',wire(identity));encodeIdentity('certificate',wire(certificate));
 accounts.push({account_id:id(i),device_id:id(10+i),identity,certificate,root_fingerprint:fingerprint,certificate_digest:identityDigest('certificate',wire(certificate)),roster_digest:hash(20+i),session_secret:b64(Buffer.alloc(32,70+i))});
}
const groups=[{id:id(30),owner:accounts[0].account_id,kind:'shared',policy_digest:hash(30),epoch_digest:hash(31)},{id:id(40),owner:accounts[2].account_id,kind:'private',policy_digest:hash(40),epoch_digest:hash(41)}];
const a=accounts[0],g=groups[0];
const context={contract:'p02-v1',protocol:'anynote',protocol_version:1,purpose:'object-context',service_id:service,group_id:g.id,object_kind:'thread',object_id:id(60),revision_id:id(61),operation_id:id(62),thread_id:null,action:'create',author:{account_id:a.account_id,device_id:a.device_id,root_fingerprint:a.root_fingerprint,recovery_generation:'0',roster:{version:'0',digest:a.roster_digest}},policy:{membership:{version:'0',digest:g.policy_digest},key_epoch:'0',epoch_digest:g.epoch_digest,history_checkpoint_digest:null},parents:[],attachments:[],payload_schema:1,archived:false};
const payload=JSON.parse(readFileSync(new URL('../../fixtures/protocol/p02/v1/crypto.json',import.meta.url))).objects.payload;
payload.context=context;payload.markdown='';payload.title='PUBLIC SQL integration thread';payload.tags=[];payload.metadata_kind='content';
const bundle=encryptObjectForEvaluation(wire(payload),Buffer.alloc(32,90),sodium.crypto_sign_seed_keypair(Buffer.alloc(32,1)).privateKey,{objectKey:Buffer.alloc(32,91),nonce:Buffer.alloc(24,92),wrapNonce:Buffer.alloc(24,93)});
const request={group_id:g.id,object_id:context.object_id,object_kind:context.object_kind,thread_id:null,action:'create',bundle};
const input=signingInput('header',wire(bundle.envelope.header));
const fixture={purpose:'PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION',service_id:service,accounts,groups,request,canonical_header:input.subarray(input.indexOf(0)+1).toString(),signing_input_hex:input.toString('hex'),signature_hex:Buffer.from(bundle.envelope.signature,'base64url').toString('hex'),public_key_hex:Buffer.from(a.certificate.body.device_signing_key,'base64url').toString('hex'),expected_bundle_digest:digest('bundle',wire(bundle))};
const output=new URL('../../apps/api/storage/framework/testing/p04-fixtures.json',import.meta.url);mkdirSync(new URL('.',output),{recursive:true});writeFileSync(output,JSON.stringify(fixture));
console.log('PASS: disposable three-account signed identity/certificate/encrypted-object corpus');
