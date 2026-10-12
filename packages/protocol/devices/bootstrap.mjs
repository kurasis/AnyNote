// Public immutable bootstrap journal: no R or root/device private key is stored here.
import {authValue} from '../auth-client.mjs';
import {verifiedSnapshot} from './client.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
import {wire} from '../adapters/codecs/identity-codec.mjs';
import {ensure} from '../vault/store.mjs';
export function bootstrapControl(request,pins,device){
 authValue('register-request',request);const event=request.roster;
 ensure(event.body.kind==='register'&&event.body.operation_id===request.operation_id,'INVALID_REQUEST');
 const proof=verifiedSnapshot({identity:request.identity,events:[event],head:{version:'0',digest:stateDigest('event',wire(event))},generation:'0'},pins),entry=proof.details.devices.find(d=>d.device_id===device.device_id),cert=event.body.payload.certificate.body;
 ensure(entry?.status==='ACTIVE'&&cert.device_id===device.device_id&&cert.device_signing_key===device.signing_key&&cert.device_encryption_key===device.encryption_key,'DEVICE_KEY_MISMATCH');
 return {purpose:'p08-installation-control',version:1,identity:null,head:null,generation:null,pages:[],staging:null,pending:null,kit_verified:true,registration_request:structuredClone(request)};
}
