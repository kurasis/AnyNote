// Portable byte decoders reject noncanonical base64 padding by throwing, while
// Node Buffer decodes it permissively. AJV formats must return false for either
// invalid encoding, so malformed public input stays a typed schema denial.
import Ajv2020 from 'ajv/dist/2020.js';
export default class PortableAjv extends Ajv2020 {
  compile(schema) {
    // Codec tables enumerate the complete frozen protocol, even when this
    // process only exports an archive. Compile a table entry on its first
    // validation, before inspecting its data, rather than generating every
    // unused validator during helper startup. AJV still checks the same schema.
    if(Object.keys(schema).length!==1||typeof schema.$ref!=='string')return super.compile(schema);
    let compiled;
    const prepare=()=>compiled??=super.compile(schema);
    const validate=data=>prepare()(data);
    Object.defineProperty(validate,'errors',{get:()=>compiled?.errors??null});
    return validate;
  }
  addFormat(name,format) {
    if(typeof format==='function'){
      const predicate=format;
      format=value=>{try{return predicate(value);}catch{return false;}};
    }
    return super.addFormat(name,format);
  }
}
