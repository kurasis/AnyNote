// Portable byte decoders reject noncanonical base64 padding by throwing, while
// Node Buffer decodes it permissively. AJV formats must return false for either
// invalid encoding, so malformed public input stays a typed schema denial.
import Ajv2020 from 'ajv/dist/2020.js';
export default class PortableAjv extends Ajv2020 {
  addFormat(name,format) {
    if(typeof format==='function'){
      const predicate=format;
      format=value=>{try{return predicate(value);}catch{return false;}};
    }
    return super.addFormat(name,format);
  }
}
