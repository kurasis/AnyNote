import Ajv from 'ajv/dist/2020.js';
import schemas from '../../contracts/generated/runtime-schemas.json' with {type:'json'};
import {formats} from '../auth-formats.mjs';
import {AuthClient,boundedResponse} from '../auth-client.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {ensure} from '../vault/store.mjs';
const ajv=new Ajv({strict:true,ownProperties:true});for(const[k,v]of Object.entries(formats))ajv.addFormat(k,v);for(const s of schemas)ajv.addSchema(s);
const doc=schemas.find(s=>s.$id==='urn:anynote:p10:shared:v1'),validators=new Map(Object.keys(doc.$defs).map(k=>[k,ajv.compile({$ref:doc.$id+'#/$defs/'+k})]));
export function sharedValue(kind,value){ensure(validators.get(kind)?.(value),'INVALID_SHARED_DTO');return value;}
export class SharedClient {
 #csrf;
 constructor(auth){ensure(auth instanceof AuthClient,'AUTH_CLIENT_REQUIRED');this.auth=auth;}
 async call(path,requestKind,responseKind,body){
  ensure(/^\/(?:groups\/[A-Za-z0-9_-]{22}\/(?:journal|invites|accept|policy|owner-consent|history|cancel|epoch\/(?:begin|page|commit))|me\/group-receipts\/[A-Za-z0-9_-]{22}\?family=(?:invite|accept|policy|consent|begin|commit|history|cancel)|me\/close-account|me\/group-invitations(?:\?after=[A-Za-z0-9_-]{22})?)$/.test(path),'INVALID_SHARED_PATH');
  if(requestKind){sharedValue(requestKind,body);this.#csrf??=(await this.auth.csrf()).csrf_token;ensure(JSON.stringify(body).length<=4194304,'RESOURCE_LIMIT');}
  const response=await this.auth.fetcher(this.auth.issuer+'/api/v1'+path,{method:requestKind?'POST':'GET',credentials:'include',cache:'no-store',redirect:'error',headers:{Accept:'application/json',...(requestKind?{'Content-Type':'application/json','X-CSRF-TOKEN':this.#csrf}:{})},...(requestKind?{body:JSON.stringify(body)}:{})});
  const limit=response.ok?4194304:4096,value=strictJson(await boundedResponse(response,limit),limit);
  if(!response.ok){this.#csrf=undefined;throw Error(value.error?.code??'SHARING_DENIED');}sharedValue(responseKind,value);
  if(path.startsWith('/me/group-receipts/'))ensure(value.operation_id===path.split('/')[3].split('?')[0],'CONTEXT_MISMATCH');
  if(path==='/me/close-account')ensure(value.operation_id===body.operation_id,'CONTEXT_MISMATCH');
  if(path.startsWith('/groups/')){const group=path.split('/')[2];ensure(value.group_id===group,'CONTEXT_MISMATCH');if(body){const r=body.invitation??body.acceptance??body.policy??body.intent??body.commit??body.history;ensure(value.operation_id===(r?.body.operation_id??body.operation_id??body.page?.operation_id),'CONTEXT_MISMATCH');}}
  return value;
 }
}
