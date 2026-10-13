import Ajv from 'ajv/dist/2020.js';
import schemas from '../../contracts/generated/runtime-schemas.json' with {type:'json'};
import {formats} from '../auth-formats.mjs';
import {ensure} from '../vault/store.mjs';
const ajv=new Ajv({strict:true,ownProperties:true});for(const [k,v]of Object.entries(formats))ajv.addFormat(k,v);for(const s of schemas)ajv.addSchema(s);
const doc=schemas.find(s=>s.$id==='urn:anynote:p12:files:v1'),validators=new Map(Object.keys(doc.$defs).map(k=>[k,ajv.compile({$ref:doc.$id+'#/$defs/'+k})]));
export function fileValue(kind,value){ensure(validators.get(kind)?.(value),'INVALID_FILE_DTO');return value;}
