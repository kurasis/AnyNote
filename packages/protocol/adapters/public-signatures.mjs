// Public signature adapter used by browser workers and Node contract tests.
// It proves bytes/signatures only; current SQL policy is independent authority.
import Ajv2020 from 'ajv/dist/2020.js';
import canonicalize from 'canonicalize';
import sodium from 'libsodium-wrappers-sumo';
import {strictJson, requireCondition as check} from '../src/strict-json.mjs';
import file from '../../contracts/p02-file-c1.schema.json' with {type:'json'};
import identity from '../../contracts/p02-identity-c1.schema.json' with {type:'json'};
import state from '../../contracts/p02-state-c1.schema.json' with {type:'json'};
import group from '../../contracts/p02-group-c2.schema.json' with {type:'json'};
import complete from '../../contracts/p02-v1.schema.json' with {type:'json'};
await sodium.ready;
const encoder = new TextEncoder();
const ajv=new Ajv2020({strict:true,ownProperties:true});
const binary=s=>{
 try {const b=sodium.from_base64(s,sodium.base64_variants.URLSAFE_NO_PADDING);return sodium.to_base64(b,sodium.base64_variants.URLSAFE_NO_PADDING)===s?b:null;} catch {return null;}
};
for(const length of [12,16,24,32,48,64])ajv.addFormat('base64url-'+length,s=>binary(s)?.length===length);
ajv.addFormat('base64url-variable',s=>binary(s)!==null);
for(const max of ['u63','119','120','199','200','65536','100000','8388608','8388624','1000000000','9223372036854775807']){const limit=max==='u63'?'9223372036854775807':max;ajv.addFormat('decimal-'+max,s=>/^(0|[1-9][0-9]*)$/.test(s)&&s.length<=limit.length&&BigInt(s)<=BigInt(limit));}
for(const schema of [file,identity,state,group,complete])ajv.addSchema(schema);
const validate=ajv.compile({$ref:complete.$id+'#/$defs/header'});
export function publicSigningBytes(headerBytes){
 const header=strictJson(headerBytes,65536);check(validate(header),'MALFORMED_ENVELOPE');
 const context=header.context;
 let last=null;
 for(const p of context.parents){check(last===null||last<p.revision_id,'MALFORMED_ENVELOPE');check(p.revision_id!==context.revision_id,'MALFORMED_ENVELOPE');last=p.revision_id;}
 last=null;
 for(const a of context.attachments){const id=a.file_id+'/'+a.file_version_id;check(last===null||last<id,'MALFORMED_ENVELOPE');last=id;}
 check((context.object_kind==='entry')===(context.thread_id!==null),'MALFORMED_ENVELOPE');
 check(context.object_kind==='entry'||context.attachments.length===0,'MALFORMED_ENVELOPE');
 check((context.action==='create')===(context.parents.length===0),'MALFORMED_ENVELOPE');
 return encoder.encode('AnyNote/p02-v1/sign/object-revision\0'+canonicalize(header));
}
export function verifyPublicHeader(headerBytes,signature,publicKey){
 check(signature instanceof Uint8Array&&signature.length===64&&publicKey instanceof Uint8Array&&publicKey.length===32,'INVALID_SIGNATURE');
 check(sodium.crypto_sign_verify_detached(signature,publicSigningBytes(headerBytes),publicKey),'INVALID_SIGNATURE');
 return true;
}
export function signPublicHeader(headerBytes,secretKey){
 check(secretKey instanceof Uint8Array&&secretKey.length===64,'INVALID_KEY_LENGTH');
 return sodium.crypto_sign_detached(publicSigningBytes(headerBytes),secretKey);
}
