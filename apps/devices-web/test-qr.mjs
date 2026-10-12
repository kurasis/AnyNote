// Maintained image-codec roundtrip; no crypto/authorization/physical-camera claim.
import z from '@zxing/library';
import {randomBytes} from 'node:crypto';
const {BrowserQRCodeSvgWriter,QRCodeReader,BinaryBitmap,HybridBinarizer,RGBLuminanceSource,EncodeHintType,DecodeHintType}=z;
const old=globalThis.document;
try{
 globalThis.document={createElementNS(_ns,name){return {name,attrs:{},children:[],setAttributeNS(_ns,key,value){this.attrs[key]=value;},appendChild(child){this.children.push(child);}};}};
 let checks=0;
 for(const size of [64,256,1000,1500])for(let run=0;run<4;run++){
  const value=JSON.stringify({purpose:'synthetic-QR-codec-only',data:randomBytes(size).toString('base64url')}),svg=new BrowserQRCodeSvgWriter().write(value,1024,1024,new Map([[EncodeHintType.ERROR_CORRECTION,'M']])),pixels=new Uint8ClampedArray(1024*1024).fill(255);
  for(const rect of svg.children){const a=rect.attrs;for(let y=Number(a.y);y<Number(a.y)+Number(a.height);y++)pixels.fill(0,y*1024+Number(a.x),y*1024+Number(a.x)+Number(a.width));}
  const bitmap=new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(pixels,1024,1024))),decoded=new QRCodeReader().decode(bitmap,new Map([[DecodeHintType.PURE_BARCODE,true]])).getText();if(decoded!==value)throw Error('QR_ROUNDTRIP_MISMATCH');checks++;
 }
 console.log('PASS maintained dense QR image-codec roundtrips',checks);
}finally{globalThis.document=old;}
