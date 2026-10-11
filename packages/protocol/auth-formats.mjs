import {Buffer} from './adapters/bytes.mjs';
import schemas from '../contracts/generated/runtime-schemas.json' with {type:'json'};
const names=new Set();
function visit(value){if(value&&typeof value==='object'){if(value.format)names.add(value.format);Object.values(value).forEach(visit);}}
schemas.forEach(visit);
export const formats=Object.fromEntries([...names].map(name=>[name,value=>{
  if(typeof value!=='string')return false;
  if(name.startsWith('decimal-')){const max=name==='decimal-u63'?9223372036854775807n:BigInt(name.slice(8));return /^(0|[1-9][0-9]*)$/.test(value)&&value.length<=String(max).length&&BigInt(value)<=max;}
  if(!/^[A-Za-z0-9_-]*$/.test(value))return false;
  let b;try{b=Buffer.from(value,'base64url');}catch{return false;}
  if(b.toString('base64url')!==value)return false;
  if(/^base64url-\d+$/.test(name))return b.length===Number(name.slice(10));
  if(name==='base64url-variable')return true;
  if(name==='base64url-sealed')return b.length>=48&&b.length<=4096;
  if(name.startsWith('bounded-binary-'))return b.length>=(name.endsWith('4096')?48:18)&&b.length<=Number(name.slice(15));
  throw Error('UNSUPPORTED_FORMAT');
}]));
