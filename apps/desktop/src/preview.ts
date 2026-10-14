// This window has no native IPC permissions. It receives one authenticated file from Rust.
// @ts-expect-error Existing independently tested P13 worker boundary is JavaScript.
import {PreviewClient} from '../../../packages/content-browser/preview-client.mjs';
import './style.css';
const client=new PreviewClient(),status=document.getElementById('status')!,text=document.getElementById('text')!,canvas=document.getElementById('canvas') as HTMLCanvasElement;
let received=false;
window.addEventListener('anynote-preview',async(event:Event)=>{
 if(received)return;received=true;const value=(event as CustomEvent).detail;
 try{
  if(typeof value?.bytes!=='string'||value.bytes.length>22369624)throw Error('PREVIEW_RESOURCE_LIMIT');
  const raw=atob(value.bytes.replace(/-/g,'+').replace(/_/g,'/')),bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));value.bytes='';
  const pdf=bytes.length>=5&&new TextDecoder().decode(bytes.subarray(0,5))==='%PDF-';
  const image=bytes[0]===137||bytes[0]===255||new TextDecoder().decode(bytes.subarray(0,4))==='RIFF';
  const result=await client.render(pdf?'pdf':image?'image':'text',bytes);
  if(result.bitmap){canvas.width=result.bitmap.width;canvas.height=result.bitmap.height;canvas.getContext('2d')!.drawImage(result.bitmap,0,0);result.bitmap.close();canvas.hidden=false;}
  text.textContent=result.text??'';status.textContent='Verified file · isolated preview';
 }catch{status.textContent=localStorage.getItem('language')==='ru'?'Просмотр недоступен. Сохраните файл из основного окна.':'Preview unavailable. Save the file from the main window.';}
});
document.addEventListener('visibilitychange',()=>{if(document.hidden){client.close();canvas.width=canvas.height=0;text.textContent='';status.textContent='Locked';}});
