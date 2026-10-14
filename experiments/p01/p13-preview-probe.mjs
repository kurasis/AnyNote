// Actual shipped isolated viewer diagnostic. No vault/physical phase acceptance inferred.
import {chromium} from 'playwright-core';
import {mkdtempSync,mkdirSync,existsSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
const root=resolve(import.meta.dirname,'../..'),scratch=mkdtempSync(join(tmpdir(),'anynote-p13-preview-'));
const report={purpose:'P13 actual shipped isolated viewer development diagnostic',status:'PENDING',source_commit:spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).stdout.trim(),physical_acceptance:false,checks:[]};let context;
try{
 const db=join(process.env.HOME,'.pki/nssdb');mkdirSync(db,{recursive:true});if(!existsSync(join(db,'cert9.db'))&&spawnSync('certutil',['-N','--empty-password','-d','sql:'+db]).status!==0)throw Error('NSS_INIT');
 if(spawnSync('certutil',['-A','-d','sql:'+db,'-n','AnyNote P06 disposable CA','-t','C,,','-i',root+'/.local/p06/tls/ca.crt']).status!==0)throw Error('NSS_TRUST');
 context=await chromium.launchPersistentContext(join(scratch,'profile'),{executablePath:process.env.CHROMIUM_EXECUTABLE??'/usr/bin/google-chrome',headless:true,chromiumSandbox:true,args:['--host-resolver-rules=MAP app.anynote.test 127.0.0.1,MAP api.anynote.test 127.0.0.1','--no-proxy-server']});
 const page=await context.newPage();let foreign=0;page.on('request',r=>{if(!['app.anynote.test','api.anynote.test'].includes(new URL(r.url()).hostname))foreign++;});
 await page.goto('https://app.anynote.test:18443/auth/notes.html');
 report.checks=await page.evaluate(async()=>{
  const {PreviewClient}=await import('/auth/notes.js'),client=new PreviewClient(),checks=[];
  const check=(value,name)=>{if(!value)throw Error(name);checks.push(name);};
  const literal=await client.render('text',new TextEncoder().encode('<script>literal only</script>'));check(literal.text==='<script>literal only</script>','LITERAL_TEXT');
  const canvas=document.createElement('canvas');canvas.width=64;canvas.height=32;canvas.getContext('2d').fillRect(0,0,64,32);const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));
  const image=await client.render('image',new Uint8Array(await blob.arrayBuffer()));check(image.bitmap.width===64&&image.bitmap.height===32&&image.thumbnail.length<=262144,'ACTUAL_RASTER_AND_THUMBNAIL');image.bitmap.close();image.thumbnail.fill(0);
  const stream='BT /F1 18 Tf 20 80 Td (P13 PUBLIC PDF) Tj ET',objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 120] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>','<< /Length '+stream.length+' >>\nstream\n'+stream+'\nendstream'];
  let pdf='%PDF-1.4\n',offsets=[0];for(let n=0;n<objects.length;n++){offsets.push(pdf.length);pdf+=(n+1)+' 0 obj\n'+objects[n]+'\nendobj\n';}const xref=pdf.length;pdf+='xref\n0 6\n0000000000 65535 f \n'+offsets.slice(1).map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+xref+'\n%%EOF\n';
  const rendered=await client.render('pdf',new TextEncoder().encode(pdf));check(rendered.pages===1&&rendered.text.includes('P13 PUBLIC PDF')&&rendered.bitmap.width>0,'ACTUAL_MAINTAINED_PDF');rendered.bitmap.close();rendered.thumbnail.fill(0);
  for(const [kind,data,code]of [['pdf','%PDF-1.7\n<< /JavaScript (evil) >>\n%%EOF','PREVIEW_ACTIVE_CONTENT_DENIED'],['image','<svg onload="evil()"></svg>','PREVIEW_UNSUPPORTED']]){const result=await client.render(kind,new TextEncoder().encode(data)).then(()=>false,e=>e.message===code);check(result,'ACTIVE_'+kind.toUpperCase()+'_DENIED');}
  const late=client.render('pdf',new TextEncoder().encode(pdf));client.close();check(await late.then(()=>false,e=>e.message==='PREVIEW_CANCELLED'),'LATE_RESULT_CANCELLED');
  for(const url of ['https://foreign.test/auth/preview-render.mjs',location.origin+'/auth/vault-worker.js',location.origin+'/auth/preview-render.mjs?name=private']){let denied=false;try{new PreviewClient(new URL(url));}catch(e){denied=e.message==='PREVIEW_ORIGIN_DENIED';}check(denied,'WRONG_RENDERER_ORIGIN_OR_ROUTE');}
  client.close();return checks;
 });
 if(foreign)throw Error('FOREIGN_PREVIEW_REQUEST');report.status='PASS';report.chromium_sandbox=true;report.foreign_requests=foreign;
}catch(error){report.status='FAIL';report.reason=/^[A-Z_]+$/.test(error.message)?error.message:'BROWSER_VIEWER_FAILURE';process.exitCode=1;}
finally{await context?.close();rmSync(scratch,{recursive:true,force:true});mkdirSync(root+'/artifacts/p13',{recursive:true});writeFileSync(root+'/artifacts/p13/preview-probe.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));}
