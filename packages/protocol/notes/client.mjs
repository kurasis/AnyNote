import Ajv from 'ajv/dist/2020.js';
import schemas from '../../contracts/generated/runtime-schemas.json' with {type:'json'};
import {formats} from '../auth-formats.mjs';
import {AuthClient,boundedResponse} from '../auth-client.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {ensure} from '../vault/store.mjs';
const ajv=new Ajv({strict:true,ownProperties:true});for(const [k,v]of Object.entries(formats))ajv.addFormat(k,v);for(const s of schemas)ajv.addSchema(s);
const doc=schemas.find(s=>s.$id==='urn:anynote:p09:notes:v1');
const validators=new Map(Object.keys(doc.$defs).map(k=>[k,ajv.compile({$ref:doc.$id+'#/$defs/'+k})]));
export function noteValue(kind,value){ensure(validators.get(kind)?.(value),'INVALID_NOTE_DTO');return value;}
export class NotesClient {
 #csrf;
 constructor(auth){ensure(auth instanceof AuthClient,'AUTH_CLIENT_REQUIRED');this.auth=auth;}
 async call(path,requestKind,responseKind,body){
  ensure(/^\/(?:groups|threads|objects|me\/content-receipts)(?:\/[A-Za-z0-9_-]+)*(?:\?after=[A-Za-z0-9_-]{1,22})?$/.test(path),'INVALID_NOTE_PATH');
  if(requestKind){noteValue(requestKind,body);this.#csrf??=(await this.auth.csrf()).csrf_token;ensure(JSON.stringify(body).length<=4194304,'RESOURCE_LIMIT');}
  const response=await this.auth.fetcher(this.auth.issuer+'/api/v1'+path,{method:requestKind?'POST':'GET',credentials:'include',cache:'no-store',redirect:'error',headers:{Accept:'application/json',...(requestKind?{'Content-Type':'application/json','X-CSRF-TOKEN':this.#csrf}:{})},...(requestKind?{body:JSON.stringify(body)}:{})});
  const limit=response.ok?(responseKind==='bundle-result'?4194304:1048576):4096;
  const value=strictJson(await boundedResponse(response,limit),limit);
  if(!response.ok){this.#csrf=undefined;const e=Error(value.error?.code??'CONTENT_DENIED');e.code=e.message;e.status=response.status;throw e;}
  noteValue(responseKind,value);
  const parts=path.split('?')[0].split('/');
  if(requestKind==='group-create')ensure(value.group_id===body.commit.body.group_id,'CONTEXT_MISMATCH');
  // A valid same-account object is still not the object requested by the caller.
  // Bind public routing before any downstream fetch, decryption or display.
  if(parts[1]==='groups'&&parts[2])ensure((value.group_id??body?.group_id)===parts[2],'CONTEXT_MISMATCH');
  if(parts[1]==='threads')ensure((value.thread_id??body?.thread_id)===parts[2],'CONTEXT_MISMATCH');
  if(parts[1]==='objects'){
   ensure((value.object?.object_id??value.object_id??body?.object_id)===parts[2],'CONTEXT_MISMATCH');
   if(parts[4])ensure(value.revision_id===parts[4],'CONTEXT_MISMATCH');
  }
  if(parts[1]==='me')ensure(value.receipt.operation_id===parts[3],'CONTEXT_MISMATCH');
  if(requestKind&&responseKind==='receipt-result'){
   const context=body.bundle.envelope.header.context;
   ensure(value.receipt.operation_id===context.operation_id&&value.receipt.revision_id===context.revision_id,'CONTEXT_MISMATCH');
  }
  return value;
 }
 async publish(request){noteValue('commit-request',request);const c=request.bundle.envelope.header.context;
  const path=c.action==='soft-delete'?'/objects/'+c.object_id+'/tombstone':c.action==='restore'?'/objects/'+c.object_id+'/restore':c.action==='create'&&c.object_kind==='thread'?'/groups/'+c.group_id+'/threads':c.action==='create'&&c.object_kind==='entry'?'/threads/'+c.thread_id+'/entries':'/objects/'+c.object_id+'/revisions';
  return this.call(path,'commit-request','receipt-result',request);
 }
 async receipt(id){return this.call('/me/content-receipts/'+id,null,'receipt-result');}
}
