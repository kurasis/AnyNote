import {PREVIEW_LIMITS, imageBounds, textPreview, pdfPreflight} from './preview-bounds.mjs';
import {getDocument, PDFWorker} from 'pdfjs-dist/build/pdf.mjs';
import {fontData} from 'anynote-p13-fonts';

const check = value => {if (!value) throw Error('PREVIEW_RESOURCE_LIMIT');};
class EmbeddedBinaryFactory {
  async fetch({kind,filename}){const path=kind+'/'+filename;if(!Object.hasOwn(fontData,path))throw Error('PREVIEW_UNSUPPORTED');const raw=atob(fontData[path]);check(raw.length<=1048576);return Uint8Array.from(raw,c=>c.charCodeAt(0));}
}
class OffscreenFactory {
  create(width,height) {check(width>0&&height>0&&width*height<=PREVIEW_LIMITS.pixels);const canvas=new OffscreenCanvas(width,height);return {canvas,context:canvas.getContext('2d',{alpha:false})};}
  reset(target,width,height) {check(width>0&&height>0&&width*height<=PREVIEW_LIMITS.pixels);target.canvas.width=width;target.canvas.height=height;}
  destroy(target) {target.canvas.width=target.canvas.height=0;target.canvas=target.context=null;}
}
async function thumbnail(canvas) {
  const scale=Math.min(1,256/canvas.width,256/canvas.height),small=new OffscreenCanvas(Math.max(1,Math.floor(canvas.width*scale)),Math.max(1,Math.floor(canvas.height*scale)));
  try{small.getContext('2d').drawImage(canvas,0,0,small.width,small.height);const blob=await small.convertToBlob({type:'image/png'});check(blob.size<=262144);return new Uint8Array(await blob.arrayBuffer());}
  finally{small.width=small.height=0;}
}
async function image(bytes) {
  const limits=imageBounds(bytes),bitmap=await createImageBitmap(new Blob([bytes],{type:limits.mime}));
  try{check(bitmap.width>0&&bitmap.height>0&&bitmap.width<=PREVIEW_LIMITS.side&&bitmap.height<=PREVIEW_LIMITS.side&&bitmap.width*bitmap.height<=PREVIEW_LIMITS.pixels);
    const canvas=new OffscreenCanvas(bitmap.width,bitmap.height);canvas.getContext('2d').drawImage(bitmap,0,0);
    try{return {bitmap:canvas.transferToImageBitmap(),thumbnail:await thumbnail(bitmap),width:bitmap.width,height:bitmap.height};}
    finally{canvas.width=canvas.height=0;}}
  finally{bitmap.close();}
}
async function pdf(bytes, pageNumber, port) {
  await pdfPreflight(bytes);
  check(port instanceof MessagePort);const worker=PDFWorker.create({port});port.start();
  const task=getDocument({data:bytes,worker,CanvasFactory:OffscreenFactory,BinaryDataFactory:EmbeddedBinaryFactory,isEvalSupported:false,enableXfa:false,
    disableFontFace:true,useSystemFonts:false,useWorkerFetch:false,useWasm:false,disableAutoFetch:true,
    disableRange:true,disableStream:true,stopAtErrors:true,maxImageSize:PREVIEW_LIMITS.pixels,
    canvasMaxAreaInBytes:PREVIEW_LIMITS.pixels*4,isOffscreenCanvasSupported:true,isImageDecoderSupported:false});
  try{const document=await task.promise;check(document.numPages>0&&document.numPages<=PREVIEW_LIMITS.pdfPages&&pageNumber>=1&&pageNumber<=document.numPages);
    const actions=await document.getJSActions(),opening=await document.getOpenAction();if(actions&&Object.keys(actions).length||opening?.action)throw Error('PREVIEW_ACTIVE_CONTENT_DENIED');
    const page=await document.getPage(pageNumber),pageActions=await page.getJSActions();if(pageActions&&Object.keys(pageActions).length)throw Error('PREVIEW_ACTIVE_CONTENT_DENIED');
    const base=page.getViewport({scale:1}),scale=Math.min(1.5,2048/base.width,2048/base.height,Math.sqrt(PREVIEW_LIMITS.pixels/(base.width*base.height)));
    const viewport=page.getViewport({scale}),canvas=new OffscreenCanvas(Math.ceil(viewport.width),Math.ceil(viewport.height));
    check(canvas.width>0&&canvas.height>0&&canvas.width*canvas.height<=PREVIEW_LIMITS.pixels);
    try{await page.render({canvasContext:canvas.getContext('2d',{alpha:false}),viewport,annotationMode:0,intent:'display'}).promise;
      const reader=page.streamTextContent({disableNormalization:false}).getReader();let text='';
      try{for(;;){const value=await reader.read();if(value.done)break;for(const item of value.value.items){if(typeof item.str==='string'){text+=item.str+' ';check(new TextEncoder().encode(text).length<=PREVIEW_LIMITS.textBytes);}}}}
      finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
      const thumb=await thumbnail(canvas);return {bitmap:canvas.transferToImageBitmap(),thumbnail:thumb,text,pages:document.numPages,page:pageNumber,width:canvas.width,height:canvas.height};
    }finally{canvas.width=canvas.height=0;page.cleanup();}
  }finally{await task.destroy();worker.destroy();port.close();}
}
let busy=false;
self.onmessage=async({data})=>{
  if(busy||!data||data.version!==1||typeof data.id!=='string'||!/^[a-f0-9]{32}$/.test(data.id)||
    !Number.isSafeInteger(data.generation)||data.generation<1||!(data.bytes instanceof Uint8Array)||
    !['text','image','pdf'].includes(data.kind)){return;}
  busy=true;const {id,generation,bytes,kind}=data;
  try{let result;if(kind==='text')result={text:textPreview(bytes)};else if(kind==='image')result=await image(bytes);else result=await pdf(bytes,data.page??1,data.parser_port);
    const transfers=[];if(result.bitmap)transfers.push(result.bitmap);if(result.thumbnail)transfers.push(result.thumbnail.buffer);
    self.postMessage({version:1,id,generation,result},transfers);
  }catch(error){const allowed=new Set(['PREVIEW_RESOURCE_LIMIT','PREVIEW_UNSUPPORTED','PREVIEW_ACTIVE_CONTENT_DENIED']);self.postMessage({version:1,id,generation,error:allowed.has(error.message)?error.message:'PREVIEW_UNSUPPORTED'});}
  finally{bytes.fill(0);busy=false;}
};
