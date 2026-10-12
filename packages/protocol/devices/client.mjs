import Ajv from 'ajv/dist/2020.js';
import schemas from '../../contracts/generated/runtime-schemas.json' with {type:'json'};
import {formats} from '../auth-formats.mjs';
import {AuthClient,boundedResponse} from '../auth-client.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {wire,same} from '../adapters/codecs/identity-codec.mjs';
import {stateDigest} from '../adapters/codecs/state-codec.mjs';
import {verifyRootIdentity} from './proofs.mjs';
import {newRosterForEvaluation,applyRosterEventForEvaluation,rosterDetails} from './roster.mjs';
import {ensure} from '../vault/store.mjs';
const ajv=new Ajv({strict:true,ownProperties:true});for(const [name,fn]of Object.entries(formats))ajv.addFormat(name,fn);for(const schema of schemas)ajv.addSchema(schema);
const doc=schemas.find(s=>s.$id==='urn:anynote:p08:devices:v1'),validators=new Map(Object.keys(doc.$defs).map(k=>[k,ajv.compile({$ref:doc.$id+'#/$defs/'+k})]));
export function deviceValue(kind,value){ensure(validators.get(kind)?.(value),'INVALID_DEVICE_DTO');return value;}
export class DevicesClient {
 #csrf;
 constructor(auth){ensure(auth instanceof AuthClient,'AUTH_CLIENT_REQUIRED');this.auth=auth;}
 async call(path,requestKind,responseKind,body,method=requestKind?'POST':'GET'){
  ensure(/^\/(?:accounts|me)(?:\/[A-Za-z0-9_-]+)*(?:\?(?:after|head)=[A-Za-z0-9_-]+(?:&(?:after|head)=[A-Za-z0-9_-]+)?)?$/.test(path),'INVALID_DEVICE_PATH');
  if(requestKind){deviceValue(requestKind,body);this.#csrf??=(await this.auth.csrf()).csrf_token;}
  const response=await this.auth.fetcher(this.auth.issuer+'/api/v1'+path,{method,credentials:'include',cache:'no-store',redirect:'error',headers:{Accept:'application/json',...(requestKind?{'Content-Type':'application/json','X-CSRF-TOKEN':this.#csrf}:{})},...(requestKind?{body:JSON.stringify(body)}:{})});
  const value=strictJson(await boundedResponse(response,response.ok?262144:4096),response.ok?262144:4096);
  if(!response.ok){this.#csrf=undefined;throw Error(value.error?.code??'DEVICE_DENIED');}
  return deviceValue(responseKind,value);
 }
 async sync(vault,account){
  ensure(/^[A-Za-z0-9_-]{22}$/.test(account),'INVALID_ACCOUNT');let cursor=null,head,identity,generation,count=0,bytes=0;
  do{const q=cursor===null?'':'?after='+cursor+'&head='+head.digest,part=await this.call('/accounts/'+account+'/roster'+q,null,'roster-result');
   if(head)ensure(same(head,part.head)&&same(identity,part.identity)&&generation===part.generation,'ROSTER_CHANGED');else{({head,identity,generation}=part);await vault.devices('snapshotStart',[identity,head,generation]);}
   bytes+=wire(part.events).length;count+=part.events.length;ensure(bytes<=16777216&&count<=1000&&part.events.length>0,'RESOURCE_LIMIT');
   ensure(part.next===null||BigInt(part.next)===BigInt(cursor??'0')+BigInt(part.events.length),'INTEGRITY_FAILURE');await vault.devices('snapshotPage',[part.events]);cursor=part.next;
  }while(cursor!==null);return vault.devices('snapshotFinish');
 }
 async snapshot(account){
  ensure(/^[A-Za-z0-9_-]{22}$/.test(account),'INVALID_ACCOUNT');let cursor=null,head,identity,generation,bytes=0;const events=[];
  do{const q=cursor===null?'':'?after='+cursor+'&head='+head.digest,part=await this.call('/accounts/'+account+'/roster'+q,null,'roster-result');
   if(head)ensure(same(head,part.head)&&same(identity,part.identity)&&generation===part.generation,'ROSTER_CHANGED');else({head,identity,generation}=part);
   bytes+=wire(part.events).length;ensure(bytes<=16777216&&events.length+part.events.length<=1000,'RESOURCE_LIMIT');
   ensure(part.next===null||(part.events.length>0&&BigInt(part.next)===BigInt(cursor??'0')+BigInt(part.events.length)),'INTEGRITY_FAILURE');events.push(...part.events);cursor=part.next;
  }while(cursor!==null);
  ensure(events.length>0&&events.length===Number(head.version)+1,'INTEGRITY_FAILURE');return {identity,events,head,generation};
 }
}
export function verifiedSnapshot(snapshot,pins,anchor=null){
 ensure(snapshot&&Array.isArray(snapshot.events)&&snapshot.events.length>0&&snapshot.events.length<=1000&&wire(snapshot).length<=16777216,'RESOURCE_LIMIT');
 const identity=verifyRootIdentity(wire(snapshot.identity),wire(pins)),roster=newRosterForEvaluation(identity);let observed=anchor===null;
 for(const event of snapshot.events){applyRosterEventForEvaluation(roster,wire(event));if(anchor&&same(rosterDetails(roster).head,anchor))observed=true;}
 const details=rosterDetails(roster);ensure(same(details.head,snapshot.head)&&details.generation===snapshot.generation,'INTEGRITY_FAILURE');ensure(observed,'ROLLBACK_QUARANTINE');
 return {identity,roster,details};
}
export function historicalSnapshot(snapshot,pins,head){
 const index=snapshot.events.findIndex(e=>e.body.version===head.version&&stateDigest('event',wire(e))===head.digest);ensure(index>=0,'UNANCHORED_HISTORY');
 return verifiedSnapshot({identity:snapshot.identity,events:snapshot.events.slice(0,index+1),head,generation:snapshot.events[index].body.generation},pins);
}
