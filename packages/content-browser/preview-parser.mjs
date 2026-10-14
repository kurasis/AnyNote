import {WorkerMessageHandler} from 'pdfjs-dist/build/pdf.worker.mjs';
// The host owns this worker separately and terminates it together with rendering.
// No nested worker can outlive a vault lock, visibility change or timeout.
let connected=false;
self.onmessage=event=>{
  if(connected||event.data?.kind!=='p13-parser-connect'||event.ports.length!==1)return;
  connected=true;const port=event.ports[0];WorkerMessageHandler.initializeFromPort(port);port.start();
};
