export const PREVIEW_LIMITS = Object.freeze({textBytes: 1048576, imageBytes: 16777216, pdfBytes: 8388608,
  pixels: 4000000, side: 4096, pdfPages: 32, pdfStreams: 256, inflatedStreamBytes: 16777216,
  inflatedTotalBytes: 33554432, deadlineMs: 10000, thumbnailPixels: 65536});
const check = (value, code = 'PREVIEW_RESOURCE_LIMIT') => {if (!value) throw Error(code);};
const ascii = bytes => new TextDecoder('latin1').decode(bytes);
const dimensions = (width, height) => {check(Number.isSafeInteger(width) && Number.isSafeInteger(height) &&
  width > 0 && height > 0 && width <= PREVIEW_LIMITS.side && height <= PREVIEW_LIMITS.side && width * height <= PREVIEW_LIMITS.pixels);return {width,height};};
export function imageBounds(bytes) {
  check(bytes instanceof Uint8Array && bytes.length <= PREVIEW_LIMITS.imageBytes && bytes.length >= 12);
  const view = new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  if (bytes[0]===137 && ascii(bytes.subarray(1,8))==='PNG\r\n\x1a\n') {
    check(bytes.length>=33 && ascii(bytes.subarray(12,16))==='IHDR','PREVIEW_UNSUPPORTED');
    let offset=8,count=0,ended=false;while(offset+12<=bytes.length){const size=view.getUint32(offset);check(size<=bytes.length-offset-12&&++count<=4096,'PREVIEW_UNSUPPORTED');
      const chunk=ascii(bytes.subarray(offset+4,offset+8));check(chunk!=='acTL'&&!(chunk==='IHDR'&&offset!==8)&&!ended,'PREVIEW_UNSUPPORTED');if(chunk==='IEND'){check(size===0,'PREVIEW_UNSUPPORTED');ended=true;}offset+=12+size;}
    check(offset===bytes.length&&ended,'PREVIEW_UNSUPPORTED');return {mime:'image/png',...dimensions(view.getUint32(16),view.getUint32(20))};
  }
  if(bytes[0]===255 && bytes[1]===216){
    let offset=2,count=0,frame=null,ended=false;
    while(offset<bytes.length){
      check(bytes[offset]===255&&++count<=4096,'PREVIEW_UNSUPPORTED');while(bytes[offset]===255)offset++;
      const marker=bytes[offset++];
      if(marker===0xd9){ended=true;break;}
      check(![0xd8,0xdc,0x00].includes(marker),'PREVIEW_UNSUPPORTED');
      if(marker>=0xd0&&marker<=0xd7)continue;
      check(offset+2<=bytes.length,'PREVIEW_UNSUPPORTED');const size=view.getUint16(offset);check(size>=2&&offset+size<=bytes.length,'PREVIEW_UNSUPPORTED');
      if([0xc0,0xc1,0xc2].includes(marker)){check(!frame&&size>=8,'PREVIEW_UNSUPPORTED');frame=dimensions(view.getUint16(offset+5),view.getUint16(offset+3));}
      else if(marker>=0xc0&&marker<=0xcf&&!([0xc4,0xc8,0xcc].includes(marker)))throw Error('PREVIEW_UNSUPPORTED');
      offset+=size;
      if(marker===0xda){check(frame,'PREVIEW_UNSUPPORTED');while(offset<bytes.length){if(bytes[offset]!==255){offset++;continue;}let next=offset+1;while(bytes[next]===255)next++;if(bytes[next]===0||bytes[next]>=0xd0&&bytes[next]<=0xd7){offset=next+1;continue;}break;}}
    }
    check(frame&&ended&&offset===bytes.length,'PREVIEW_UNSUPPORTED');return {mime:'image/jpeg',...frame};
  }
  if(ascii(bytes.subarray(0,4))==='RIFF'&&ascii(bytes.subarray(8,12))==='WEBP'){
    check(bytes.length>=30&&view.getUint32(4,true)+8===bytes.length,'PREVIEW_UNSUPPORTED');let offset=12,count=0,canvas=null,frame=null;
    while(offset+8<=bytes.length){
      check(++count<=256,'PREVIEW_UNSUPPORTED');const kind=ascii(bytes.subarray(offset,offset+4)),size=view.getUint32(offset+4,true),start=offset+8;
      check(size<=bytes.length-start,'PREVIEW_UNSUPPORTED');const part=bytes.subarray(start,start+size),v=new DataView(part.buffer,part.byteOffset,part.byteLength);
      check(!['ANIM','ANMF'].includes(kind),'PREVIEW_UNSUPPORTED');
      if(kind==='VP8X'){check(!canvas&&size===10&&(part[0]&2)===0,'PREVIEW_UNSUPPORTED');const n=o=>part[o]+(part[o+1]<<8)+(part[o+2]<<16)+1;canvas=dimensions(n(4),n(7));}
      if(kind==='VP8 '){check(!frame&&size>=10&&part[3]===0x9d&&part[4]===1&&part[5]===0x2a,'PREVIEW_UNSUPPORTED');frame=dimensions(v.getUint16(6,true)&0x3fff,v.getUint16(8,true)&0x3fff);}
      if(kind==='VP8L'){check(!frame&&size>=5&&part[0]===0x2f,'PREVIEW_UNSUPPORTED');const n=v.getUint32(1,true);frame=dimensions((n&0x3fff)+1,((n>>>14)&0x3fff)+1);}
      offset=start+size+(size%2);
    }
    check(offset===bytes.length&&frame&&(!canvas||canvas.width>=frame.width&&canvas.height>=frame.height),'PREVIEW_UNSUPPORTED');return {mime:'image/webp',...(canvas??frame)};
  }
  throw Error('PREVIEW_UNSUPPORTED');
}
export function textPreview(bytes) {
  check(bytes instanceof Uint8Array&&bytes.length<=PREVIEW_LIMITS.textBytes);
  let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{throw Error('PREVIEW_UNSUPPORTED');}
  check(!text.includes('\0')&&![...text.slice(0,4096)].some(c=>c.charCodeAt(0)<32&&!['\n','\r','\t'].includes(c)),'PREVIEW_UNSUPPORTED');return text;
}
// Conservative resource preflight, not a replacement for the maintained PDF parser.
// Ambiguous, encrypted, object-stream, unsupported-filter or complex PDFs retain safe download.
export async function pdfPreflight(bytes) {
  check(bytes instanceof Uint8Array&&bytes.length>=8&&bytes.length<=PREVIEW_LIMITS.pdfBytes);
  const raw=ascii(bytes);check(raw.startsWith('%PDF-')&&/%%EOF\s*$/.test(raw),'PREVIEW_UNSUPPORTED');
  const streamPattern=/(?:^|[\s>])stream(?:\r\n|\n)/g;let match,total=0,count=0,lastEnd=0;
  while((match=streamPattern.exec(raw))!==null){
    check(++count<=PREVIEW_LIMITS.pdfStreams);
    const objectStart=raw.lastIndexOf(' obj',match.index),dictionary=raw.slice(Math.max(lastEnd,objectStart),match.index);
    check(dictionary.length<=65536&&!/\/[\w]*#[0-9a-f]{2}/i.test(dictionary)&&!/\/(?:ObjStm|Encrypt)\b/.test(dictionary),'PREVIEW_UNSUPPORTED');
    const lengths=[...dictionary.matchAll(/\/Length\s+(\d+)(?:\s+(\d+)\s+R)?\b/g)];check(lengths.length===1,'PREVIEW_UNSUPPORTED');
    let length=Number(lengths[0][1]);if(lengths[0][2]!==undefined){const ref=new RegExp('(?:^|[\\r\\n])'+length+'\\s+'+lengths[0][2]+'\\s+obj\\s+(\\d+)\\s+endobj','g'),values=[...raw.matchAll(ref)];check(values.length===1,'PREVIEW_UNSUPPORTED');length=Number(values[0][1]);}
    const start=streamPattern.lastIndex,end=start+length;check(Number.isSafeInteger(length)&&length>=0&&end<=bytes.length&&/^(?:\r\n|\n)?endstream\b/.test(raw.slice(end,end+16)),'PREVIEW_UNSUPPORTED');
    const filters=[...dictionary.matchAll(/\/Filter\s*\/([A-Za-z0-9]+)/g)];check(!/\/Filter\s*\[/.test(dictionary)&&filters.length<=1,'PREVIEW_UNSUPPORTED');
    check(!/\/Filter\b/.test(dictionary)||filters.length===1,'PREVIEW_UNSUPPORTED');const filter=filters[0]?.[1];check(!filter||['FlateDecode','DCTDecode'].includes(filter),'PREVIEW_UNSUPPORTED');
    if(filter==='FlateDecode'){
      const reader=new Blob([bytes.subarray(start,end)]).stream().pipeThrough(new DecompressionStream('deflate')).getReader();let observed=0;
      try{for(;;){const part=await reader.read();if(part.done)break;observed+=part.value.length;total+=part.value.length;check(observed<=PREVIEW_LIMITS.inflatedStreamBytes&&total<=PREVIEW_LIMITS.inflatedTotalBytes);}}
      catch(error){await reader.cancel().catch(()=>{});throw Error(error.message==='PREVIEW_RESOURCE_LIMIT'?error.message:'PREVIEW_UNSUPPORTED');}
      finally{reader.releaseLock();}
    }else if(filter==='DCTDecode')imageBounds(bytes.subarray(start,end));
    else{total+=length;check(total<=PREVIEW_LIMITS.inflatedTotalBytes);}
    lastEnd=end;streamPattern.lastIndex=end;
  }
  const publicText=raw.replace(/stream(?:\r\n|\n)[\s\S]*?endstream/g,'');
  check(!/\/(?:ObjStm|Encrypt|JavaScript|JS|Launch|RichMedia)\b/.test(publicText),'PREVIEW_ACTIVE_CONTENT_DENIED');
  check(!/\/[\w]*#[0-9a-f]{2}/i.test(publicText),'PREVIEW_UNSUPPORTED');
  return {streams:count,inflated_bytes:total};
}
