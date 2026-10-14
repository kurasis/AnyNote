import canonicalize from 'canonicalize';
// Additive P07 public control frame. It is signed by the locally encrypted device
// signing key; it is never disguised as a frozen P02 export-evidence/cache record.
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {sodium,Buffer,b64,un64} from '../adapters/primitives.mjs';
import {ensure,same} from './store.mjs';
export const manifestBody=(scope,pins,vault_id,file_profile,content_profile)=>({contract:'p07-local-v1',protocol:'anynote',protocol_version:1,purpose:'local-vault-manifest',scope,pins,vault_id,...(file_profile?{file_profile}:{}),...(content_profile?{content_profile}:{})});
const input=body=>Buffer.concat([Buffer.from('AnyNote/P07/local-manifest\0'),Buffer.from(canonicalize(body))]);
export const signManifest=(scope,pins,vault_id,secret,file_profile,content_profile)=>{const body=manifestBody(scope,pins,vault_id,file_profile,content_profile);return {body,signature:b64(sodium.crypto_sign_detached(input(body),secret))};};
export function verifyManifest(state,publicKey){
 const m=state.manifest;ensure(m&&Object.keys(m).sort().join(',')==='body,signature'&&same(m.body,manifestBody(state.scope,state.pins,state.vault_id,state.file_profile,state.content_profile)),'INTEGRITY_FAILURE');
 ensure(typeof m.signature==='string'&&un64(m.signature).length===64&&b64(un64(m.signature))===m.signature&&sodium.crypto_sign_verify_detached(un64(m.signature),input(m.body),publicKey),'INTEGRITY_FAILURE');
}
