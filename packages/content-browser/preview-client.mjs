import {PREVIEW_LIMITS} from './preview-bounds.mjs';
const random=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(n=>n.toString(16).padStart(2,'0')).join('');
export class PreviewClient {
  #worker;#parser;#pending;#generation=1;#url;
  constructor(url=new URL('/auth/preview-render.mjs',location.href)){if(url.origin!==location.origin||url.pathname!=='/auth/preview-render.mjs'||url.search||url.hash||url.username||url.password)throw Error('PREVIEW_ORIGIN_DENIED');this.#url=url.href;document.addEventListener('visibilitychange',()=>{if(document.hidden)this.close();});}
  close(reason='PREVIEW_CANCELLED'){this.#generation++;this.#worker?.terminate();this.#parser?.terminate();this.#worker=this.#parser=undefined;if(this.#pending){clearTimeout(this.#pending.timer);this.#pending.reject(Error(reason));this.#pending=undefined;}}
  render(kind,bytes,page=1){
    if(document.hidden)throw Error('RESUME_REQUIRED');if(!['pdf','text','image'].includes(kind))throw Error('PREVIEW_UNSUPPORTED');if(!(bytes instanceof Uint8Array)||bytes.length>(kind==='pdf'?PREVIEW_LIMITS.pdfBytes:kind==='text'?PREVIEW_LIMITS.textBytes:PREVIEW_LIMITS.imageBytes))throw Error('PREVIEW_RESOURCE_LIMIT');
    this.close();const generation=this.#generation,id=random();this.#worker=new Worker(this.#url,{type:'module'});
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>this.close('PREVIEW_TIMEOUT'),PREVIEW_LIMITS.deadlineMs);this.#pending={timer,reject};
      this.#worker.onerror=()=>this.close('PREVIEW_UNSUPPORTED');
      this.#worker.onmessage=({data})=>{
        if(!data||data.version!==1||data.id!==id||data.generation!==generation||generation!==this.#generation)return;
        clearTimeout(timer);this.#pending=undefined;this.#worker.terminate();this.#parser?.terminate();this.#worker=this.#parser=undefined;
        if(document.hidden){data.result?.bitmap?.close();reject(Error('RESUME_REQUIRED'));}
        else if(data.error)reject(Error(data.error));else{
          const result=data.result;
          if(!result||result.bitmap&&(!(result.bitmap instanceof ImageBitmap)||result.bitmap.width>PREVIEW_LIMITS.side||result.bitmap.height>PREVIEW_LIMITS.side||result.bitmap.width*result.bitmap.height>PREVIEW_LIMITS.pixels)||result.thumbnail&&(!(result.thumbnail instanceof Uint8Array)||result.thumbnail.length>262144)||result.text!==undefined&&(typeof result.text!=='string'||new TextEncoder().encode(result.text).length>PREVIEW_LIMITS.textBytes)){result?.bitmap?.close();reject(Error('PREVIEW_RESOURCE_LIMIT'));}
          else resolve(result);
        }
      };
      const transfers=[bytes.buffer];let parser_port;
      if(kind==='pdf'){const ports=new MessageChannel();this.#parser=new Worker(new URL('/auth/preview-parser.mjs',location.href),{type:'module'});this.#parser.onerror=()=>this.close('PREVIEW_UNSUPPORTED');this.#parser.postMessage({kind:'p13-parser-connect'},[ports.port2]);parser_port=ports.port1;transfers.push(parser_port);}
      this.#worker.postMessage({version:1,id,generation,kind,bytes,page,parser_port},transfers);
    });
  }
}
