import Ajv from 'ajv/dist/2020.js';
import schemas from '../../contracts/generated/runtime-schemas.json' with {type:'json'};
import {formats} from '../auth-formats.mjs';
import {AuthClient,boundedResponse} from '../auth-client.mjs';
import {strictJson} from '../src/strict-json.mjs';
import {ensure} from '../vault/store.mjs';
const ajv=new Ajv({strict:true,ownProperties:true});for(const[k,v]of Object.entries(formats))ajv.addFormat(k,v);for(const s of schemas)ajv.addSchema(s);
const doc=schemas.find(s=>s.$id==='urn:anynote:p13:content:v1'),validators=new Map(Object.keys(doc.$defs).map(k=>[k,ajv.compile({$ref:doc.$id+'#/$defs/'+k})]));
export function contentValue(kind,value){ensure(validators.get(kind)?.(value),'INVALID_CONTENT_DTO');return value;}
export class ContentClient{
 constructor(auth){ensure(auth instanceof AuthClient,'AUTH_CLIENT_REQUIRED');this.auth=auth;}
 async call(path,kind,body,method=body?'POST':'GET'){
  ensure(/^\/exports(?:\/[A-Za-z0-9_-]{22}(?:\/(?:renew|catalog|pages|headers|records\/[A-Za-z0-9_-]{22}))?)?(?:\?start=[0-9]{1,4})?$/.test(path),'INVALID_CONTENT_PATH');
  const write=method!=='GET',csrf=write?(await this.auth.csrf()).csrf_token:undefined;
  if(body)contentValue(path==='/exports'?'export-request':'renew-request',body);
  const response=await this.auth.fetcher(this.auth.issuer+'/api/v1'+path,{method,credentials:'include',cache:'no-store',redirect:'error',headers:{Accept:'application/json',...(write?{'X-CSRF-TOKEN':csrf}:{}),...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
  const limit=response.ok?4194304:4096,value=strictJson(await boundedResponse(response,limit),limit);if(!response.ok)throw Error(value.error?.code??'CONTENT_DENIED');return contentValue(kind,value);
 }
}
// Installed at Worker construction from the build's fixed issuer, never a renderer URL.
export class ExportTransport{
 #issuer;#abort=new AbortController();
 constructor(issuer,fetcher=globalThis.fetch.bind(globalThis)){const url=new URL(issuer);ensure(url.protocol==='https:'&&url.origin===issuer&&!url.username&&!url.password,'INVALID_ISSUER');this.#issuer=issuer;this.fetcher=fetcher;}
 close(){this.#abort.abort();}
 async get(path,binary=false){ensure(/^\/exports\/[A-Za-z0-9_-]{22}(?:\/(?:catalog|pages|headers|records\/[A-Za-z0-9_-]{22}|files\/[A-Za-z0-9_-]{22}\/chunks\/[0-9]{1,3}))?(?:\?start=[0-9]{1,4})?$/.test(path),'INVALID_CONTENT_PATH');const response=await this.fetcher(this.#issuer+'/api/v1'+path,{credentials:'include',cache:'no-store',redirect:'error',signal:this.#abort.signal,headers:{Accept:binary?'application/octet-stream':'application/json'}}),limit=response.ok?(binary?8388624:4194304):4096,bytes=await boundedResponse(response,limit);if(!response.ok){const value=strictJson(bytes,4096);throw Error(value.error?.code??'CONTENT_DENIED');}return binary?bytes:strictJson(bytes,4194304);}
}
