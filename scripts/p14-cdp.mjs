// Minimal standard CDP client for the real installed WebView2, no browser replacement.
export const delay=ms=>new Promise(r=>setTimeout(r,ms));
export async function until(f,label,timeout=60000){const end=Date.now()+timeout;let last;while(Date.now()<end){try{const value=await f();if(value)return value;}catch(e){last=e;}await delay(200);}throw Error(label+(last?': '+String(last).slice(0,180):''));}
export class CDP {
 #id=0;#pending=new Map();
 constructor(socket){this.socket=socket;socket.addEventListener('message',e=>{const value=JSON.parse(e.data);if(value.id){const p=this.#pending.get(value.id);if(!p)return;this.#pending.delete(value.id);value.error?p.reject(Error(value.error.message)):p.resolve(value.result);}});socket.addEventListener('close',()=>{for(const p of this.#pending.values())p.reject(Error('CDP_CLOSED'));this.#pending.clear();});}
 static async connect(url){const socket=new WebSocket(url),client=new CDP(socket);await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});return client;}
 command(method,params={},timeout=600000){return new Promise((resolve,reject)=>{
  const id=++this.#id,timer=setTimeout(()=>{this.#pending.delete(id);reject(Error('CDP_COMMAND_TIMEOUT:'+method));},timeout);
  timer.unref();this.#pending.set(id,{resolve:value=>{clearTimeout(timer);resolve(value);},reject:error=>{clearTimeout(timer);reject(error);}});
  try{this.socket.send(JSON.stringify({id,method,params}));}catch(error){this.#pending.delete(id);clearTimeout(timer);reject(error);}
 });}
 async evaluate(expression){const result=await this.command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true,userGesture:true});if(result.exceptionDetails){const remote=result.exceptionDetails.exception;throw Error(remote?.description??(typeof remote?.value==='string'?remote.value:'WEBVIEW_EVALUATION_FAILED'));}return result.result.value;}
 close(){this.socket.close();}
}
export async function targets(){const response=await fetch('http://127.0.0.1:9223/json/list');if(!response.ok)throw Error('WEBVIEW_CDP_UNAVAILABLE');return response.json();}
export async function mainWindow(process){const target=await until(async()=>{if(process&&process.exitCode!==null)throw Error('INSTRUMENTED_PROCESS_EXITED:'+process.exitCode);return (await targets()).find(t=>t.type==='page'&&t.url.startsWith('http://tauri.localhost/')&&!t.url.includes('/auth/preview.html'));},'Real main WebView2 target');const cdp=await CDP.connect(target.webSocketDebuggerUrl);await cdp.command('Page.enable');return cdp;}
