// Owned Windows CI TLS edge. Streams actual Laravel traffic; never issues tokens or decrypts content.
import https from 'node:https';import http from 'node:http';import {readFileSync,createReadStream,statSync} from 'node:fs';import {resolve,sep} from 'node:path';
const root=resolve(import.meta.dirname,'..'),state=root+'/.local/p06',staticRoot=resolve(state,'static');
const server=https.createServer({key:readFileSync(state+'/tls/server.key'),cert:readFileSync(state+'/tls/server.crt')},(req,res)=>{
 const host=req.headers.host;
 if(req.socket.servername==='api.anynote.test'&&host==='api.anynote.test:18443'){
  const headers={...req.headers,host,'x-forwarded-proto':'https'};delete headers['x-forwarded-host'];
  const upstream=http.request({host:'127.0.0.1',port:18080,path:req.url,method:req.method,headers},response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
  upstream.on('error',()=>{if(!res.headersSent)res.writeHead(502);res.end();});req.pipe(upstream);return;
 }
 if(req.socket.servername!=='app.anynote.test'||host!=='app.anynote.test:18443'){res.writeHead(404);res.end();return;}
 try{const pathname=decodeURIComponent(new URL(req.url,'https://app.anynote.test:18443').pathname);if(pathname.includes('\\'))throw Error();const path=resolve(staticRoot,'.'+(pathname.endsWith('/')?pathname+'index.html':pathname));if(!path.startsWith(staticRoot+sep)||!statSync(path).isFile())throw Error();const ext=path.split('.').pop();res.writeHead(200,{'content-type':({html:'text/html',js:'text/javascript',mjs:'text/javascript',css:'text/css',wasm:'application/wasm',png:'image/png',svg:'image/svg+xml',json:'application/json'})[ext]??'application/octet-stream','cache-control':'no-store','x-content-type-options':'nosniff'});createReadStream(path).pipe(res);}catch{res.writeHead(404);res.end();}
});server.listen(18443,'127.0.0.1');
