import test from 'node:test';
import assert from 'node:assert/strict';
import {deflateSync} from 'node:zlib';
import {imageBounds,textPreview,pdfPreflight,PREVIEW_LIMITS} from './preview-bounds.mjs';
const pdf=(data,filter='FlateDecode')=>new Uint8Array(Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj\n<< /Length '+data.length+' /Filter /'+filter+' >>\nstream\n'),data,Buffer.from('\nendstream\nendobj\n%%EOF\n')]));
test('text preview is literal UTF-8 and denies oversized, binary and invalid bytes',()=>{
 assert.equal(textPreview(new TextEncoder().encode('<script>alert(1)</script>')),'<script>alert(1)</script>');
 for(const b of [new Uint8Array(PREVIEW_LIMITS.textBytes+1),new Uint8Array([0]),new Uint8Array([255])])assert.throws(()=>textPreview(b));
});
test('PDF preflight bounds real zlib inflation before the maintained renderer sees bytes',async()=>{
 assert.equal((await pdfPreflight(pdf(deflateSync(Buffer.from('BT (bounded) Tj ET'))))).streams,1);
 await assert.rejects(()=>pdfPreflight(pdf(deflateSync(Buffer.alloc(PREVIEW_LIMITS.inflatedStreamBytes+1)))),/PREVIEW_RESOURCE_LIMIT/);
 await assert.rejects(()=>pdfPreflight(pdf(new Uint8Array([1,2,3]),'JBIG2Decode')),/PREVIEW_UNSUPPORTED/);
});
test('encrypted, active, escaped-name and ambiguous PDF structures have explicit safe-download fallback',async()=>{
 for(const text of ['%PDF-1.7\n<< /JavaScript (evil) >>\n%%EOF','%PDF-1.7\n<< /Encrypt 1 0 R >>\n%%EOF','%PDF-1.7\n<< /Fi#6cter /FlateDecode >>\n%%EOF','%PDF-1.7\n<< /ObjStm >>\n%%EOF'])await assert.rejects(()=>pdfPreflight(new TextEncoder().encode(text)));
 const bad=new TextEncoder().encode('%PDF-1.7\n1 0 obj\n<< /Length 1 /Filter 2 0 R >>\nstream\nx\nendstream\nendobj\n%%EOF');await assert.rejects(()=>pdfPreflight(bad),/PREVIEW_UNSUPPORTED/);
});
test('active image documents, animation and oversized declared raster dimensions are denied before decode',()=>{
 for(const text of ['<svg onload="alert(1)"></svg>','<html><img src="https://foreign.test"></html>','GIF89a........'])assert.throws(()=>imageBounds(new TextEncoder().encode(text)),/PREVIEW_/);
 const b=new Uint8Array(45),v=new DataView(b.buffer);b.set([137,80,78,71,13,10,26,10]);v.setUint32(8,13);b.set(new TextEncoder().encode('IHDR'),12);v.setUint32(16,65535);v.setUint32(20,65535);b.set(new TextEncoder().encode('IEND'),37);assert.throws(()=>imageBounds(b),/PREVIEW_RESOURCE_LIMIT/);
});
