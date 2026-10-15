// Runs after the inherited actual incompressible P12 upload/download/resume case.
// Mobile viewport is desktop Chromium evidence, never physical iPhone evidence.
import {readFileSync, writeFileSync, createReadStream, mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PortableReader} from '../../packages/protocol/content/portable.mjs';
import {phrase} from '../../packages/protocol/notes/test-fixture.mjs';
import {browserMemory} from './p12-browser-memory.mjs';
import {browserHeap} from './p15-heap.mjs';
import {processMemory} from './p15-process-memory.mjs';

export async function pwaCase({page, action, check, scratch, readyWriter, commitBeforeLosingResponse}) {
  const encryptedOutboxHashes=()=>page.evaluate(async()=>{
    const {IndexedVault}=await import('/auth/vault-store.js');
    const store=await new IndexedVault(JSON.parse(document.getElementById('profiles').value)).open();
    let rows;
    try{rows=await store.transaction(false,async tx=>{const found=[];await tx.each(row=>{if(row.frame?.context?.record_kind==='outbox')found.push({id:row.id,encoded:JSON.stringify(row)});});return found;});}finally{store.close();}
    rows.sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
    return Promise.all(rows.map(async row=>({id:row.id,sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(row.encoded)))].map(b=>b.toString(16).padStart(2,'0')).join('')})));
  });
  // The inherited P12 case deliberately finishes locked. Resume through the
  // shipped unlock/proof/group flow before touching mobile content controls.
  await page.bringToFront();
  if (await page.locator('#workspace').isHidden()) {
    await readyWriter(page);
    await page.locator('#phrase').fill(phrase); await action(page, 'unlock');
  }
  await page.locator('#groups button').filter({hasText: 'PUBLIC browser shared group'}).click();
  await page.waitForFunction(() => !document.getElementById('status').dataset.busy);
  await page.locator('#threads button').filter({hasText: 'PUBLIC browser shared thread'}).click();
  await page.waitForFunction(() => !document.getElementById('status').dataset.busy);
  await page.locator('#entries button').filter({hasText: 'PUBLIC P12 attached entry'}).click();
  await page.waitForFunction(() => !document.getElementById('status').dataset.busy);
  check(await page.locator('#note-title').inputValue()==='PUBLIC P12 attached entry','P15_VERIFIED_ENTRY_TITLE_AFTER_LOCK');
  const workerPath = fileURLToPath(new URL('../../.local/p06/static/auth/sw.js', import.meta.url));
  const originalWorker = readFileSync(workerPath, 'utf8');
  const memory = browserMemory(), processes = processMemory(); let heap;
  try {
    heap = await browserHeap(page);
    const source = join(scratch, 'P12_PUBLIC_SELECTED_FILE.bin');
    let sourceBytes = 0;
    const expected = createHash('sha256');
    for await (const bytes of createReadStream(source)) { sourceBytes += bytes.length; expected.update(bytes); }
    check(sourceBytes === 1000000000, 'P15_REAL_INCOMPRESSIBLE_SOURCE_SIZE');
    const sourceHash = expected.digest('hex');
    await page.setViewportSize({width: 390, height: 844});
    await page.locator('#pwa-panes button').nth(2).click();
    check(await page.locator('.editor-pane').isVisible(), 'P15_MOBILE_CONTENT_NAVIGATION');
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'P15_NO_HORIZONTAL_MOBILE_OVERFLOW');
    await page.setViewportSize({width: 390, height: 420});
    check(await page.locator('#note-body').evaluate(e => parseFloat(getComputedStyle(e).fontSize) >= 16), 'P15_KEYBOARD_VIEWPORT_READABLE_INPUT');
    await page.locator('#note-body').scrollIntoViewIfNeeded();
    check(await page.locator('#pwa-save-state').isVisible() && await page.locator('#pwa-panes').evaluate(e=>{const r=e.getBoundingClientRect();return r.top>=0&&r.bottom<innerHeight;}),'P15_KEYBOARD_VIEWPORT_VISIBLE_SAVE_STATE');
    await page.setViewportSize({width: 390, height: 844});
    await page.locator('#language').selectOption('ru');
    check(await page.locator('#pwa-help summary').textContent() === 'Установка и хранилище', 'P15_RUSSIAN_INSTALL_GUIDANCE');
    await page.locator('#language').selectOption('en');
    const imageDirectory=fileURLToPath(new URL('../../artifacts/p15/',import.meta.url));mkdirSync(imageDirectory,{recursive:true});
    await page.screenshot({path:join(imageDirectory,'mobile-notes.png'),fullPage:true});
    const href = await page.locator('link[rel=manifest]').getAttribute('href');
    check(href === '/auth/manifest.webmanifest', 'P15_STABLE_INSTALL_MANIFEST');
    const cached = await page.evaluate(async () => {
      const registration = await navigator.serviceWorker.ready;
      const names = (await caches.keys()).filter(n => n.startsWith('anynote-p07-static-'));
      const paths = [];
      for (const name of names) for (const request of await (await caches.open(name)).keys()) paths.push(new URL(request.url).pathname);
      return {scope: registration.scope, paths, manifestType: (await caches.match('/auth/manifest.webmanifest'))?.headers.get('content-type')};
    });
    check(cached.scope.endsWith('/auth/') && cached.paths.includes('/auth/icon-192.png') && cached.paths.includes('/auth/manifest.webmanifest'), 'P15_INSTALLED_STATIC_ASSETS_CACHED');
    check(cached.manifestType?.startsWith('application/manifest+json'), 'P15_REAL_MANIFEST_MEDIA_TYPE');
    check(cached.paths.every(p => /^\/auth\/[a-z0-9.-]+$/.test(p)), 'P15_NO_API_OR_EXPORT_CACHE_ENTRIES');

    // The group still contains the actual P12 file attached to its signed entry.
    await page.locator('#export-this-group').check();
    await action(page, 'prepare-export');
    await page.locator('#export-estimate-confirm').check();
    const downloading = page.waitForEvent('download', {timeout: 600000});
    await page.locator('#portable-export').click();
    const archive = await downloading, archivePath = join(scratch, 'p15-gigabyte.age');
    await archive.saveAs(archivePath);
    await page.waitForFunction(() => !document.getElementById('status').dataset.busy, null, {timeout: 600000});
    check(!await page.locator('#status').getAttribute('data-error'), 'P15_GIGABYTE_SHIPPED_ARCHIVE_EOF');
    check(await page.locator('#save-export-kit').isVisible(), 'P15_KIT_RELEASED_ONLY_AFTER_DURABLE_ARCHIVE');
    const kitDownloading = page.waitForEvent('download');
    await page.locator('#save-export-kit').click();
    const kit = await kitDownloading, kitPath = join(scratch, 'p15-gigabyte.kit.json');
    await kit.saveAs(kitPath);
    const reader = new PortableReader(() => Readable.toWeb(createReadStream(archivePath)), JSON.parse(readFileSync(kitPath)));
    let recoveredBytes = 0;
    const recovered = createHash('sha256');
    try {
      const verified = await reader.validate();
      const file = verified.files.find(f => f.plaintext_bytes === '1000000000');
      check(verified.status === 'VERIFIED_OFFLINE' && !!file, 'P15_GIGABYTE_ARCHIVE_VERIFIED_WITHOUT_ORIGINAL_API');
      await reader.file(file.file_version_id, {
        write(bytes) { recoveredBytes += bytes.length; recovered.update(bytes); },
        finish() {}, abort() { throw Error('P15_OFFLINE_RECOVERY_ABORTED'); },
      });
    } finally { reader.close(); }
    const recoveredHash = recovered.digest('hex');
    check(recoveredBytes === 1000000000 && recoveredHash === sourceHash, 'P15_INDEPENDENT_FULL_PLAINTEXT_HASH');

    // The independent offline reader is outside the app. If its real elapsed
    // time triggered the unchanged idle fence, resume through actual unlock.
    if (await page.locator('#workspace').isHidden()) {
      await page.locator('#phrase').fill(phrase); await action(page, 'unlock');
      check(await page.locator('#workspace').isVisible(), 'P15_OFFLINE_READER_IDLE_REQUIRES_FRESH_UNLOCK');
    }

    await page.locator('#import-archive').setInputFiles(archivePath);
    await page.locator('#import-kit').setInputFiles(kitPath);
    await action(page, 'inspect-import');
    const importId=await page.locator('#resume-import-id').inputValue();
    let releasePart, partStarted, holdTimer;
    const heldPart = new Promise(resolve => { partStarted = resolve; });
    const releasedPart = new Promise(resolve => { releasePart = resolve; });
    const partRoute = '**/api/v1/uploads/*/parts/0';
    let holdOnce = true;
    await page.route(partRoute, async route => {
      if (holdOnce) { holdOnce = false; partStarted(); await releasedPart; }
      await route.continue();
    });
    await page.locator('#import-confirm').check();
    await page.locator('#copy-import').click();
    try {
      await Promise.race([heldPart, new Promise((_, reject) => { holdTimer = setTimeout(() => reject(Error('P15_IMPORT_PART_NOT_STARTED')), 300000); })]);
      await page.locator('#portable-pause').click();
    } finally { clearTimeout(holdTimer); releasePart(); }
    await page.waitForFunction(() => !document.getElementById('status').dataset.busy, null, {timeout: 300000});
    await page.unroute(partRoute);
    check((await page.locator('#portable-state').textContent()).includes('Paused'), 'P15_IMPORT_PAUSE_PRESERVES_PROTECTED_PROGRESS');
    await page.reload();
    await page.waitForFunction(()=>document.getElementById('status').dataset.state==='ready');
    await readyWriter(page);
    await page.locator('#phrase').fill(phrase);await action(page,'unlock');
    await action(page,'completed-content-jobs');
    await page.locator('#content-job-list li[data-job-id="'+importId+'"] button').filter({hasText:'Resume this import'}).click();
    await page.waitForFunction(()=>!document.getElementById('status').dataset.busy);
    check(await page.locator('#resume-import-id').inputValue()===importId,'P15_PAGE_DESTRUCTION_RETAINS_EXACT_IMPORT_JOB');
    await page.locator('#import-archive').setInputFiles(archivePath);
    await page.locator('#import-kit').setInputFiles(kitPath);
    await action(page, 'inspect-import');
    const commitPending = [];
    let importedReceipt;
    const receiptObserver = response => {
      const url = new URL(response.url());
      if (url.origin === 'https://api.anynote.test:18443' && /^\/api\/v1\/uploads\/[A-Za-z0-9_-]{22}\/commit$/.test(url.pathname) && response.ok()) {
        commitPending.push(response.json().then(value => { importedReceipt = value; }));
      }
    };
    page.on('response', receiptObserver);
    await page.locator('#import-confirm').check();
    await action(page, 'copy-import');
    await Promise.all(commitPending); page.off('response', receiptObserver);
    check((await page.locator('#portable-state').textContent()).includes('Import complete'), 'P15_REAL_GIGABYTE_PRIVATE_IMPORT_RECEIPTS');
    check(importedReceipt?.state === 'COMMITTED' && /^[A-Za-z0-9_-]{22}$/.test(importedReceipt.group_id), 'P15_IMPORTED_FILE_HAS_REAL_IMMUTABLE_RECEIPT');
    await action(page, 'refresh');
    await page.locator('#pwa-panes button').nth(0).click();
    await page.locator('#groups li[data-id="' + importedReceipt.group_id + '"] button').click();
    await page.waitForFunction(() => !document.getElementById('status').dataset.busy);
    await page.locator('#threads button').first().click();
    await page.waitForFunction(() => !document.getElementById('status').dataset.busy);
    const filePanel=page.locator('details').filter({has:page.locator('#file-source')});
    if(!await filePanel.evaluate(e=>e.open))await filePanel.locator('summary').click();
    await action(page, 'file-refresh');
    const importedDownload = page.waitForEvent('download', {timeout: 300000});
    await page.locator('#file-items li').filter({hasText: importedReceipt.file_version_id}).locator('button').filter({hasText: 'Export file'}).click();
    const importedPath = join(scratch, 'p15-imported-roundtrip.bin');
    await (await importedDownload).saveAs(importedPath);
    const importedHash = createHash('sha256'); let importedBytes = 0;
    for await (const bytes of createReadStream(importedPath)) { importedBytes += bytes.length; importedHash.update(bytes); }
    const importedDigest = importedHash.digest('hex');
    check(importedBytes === sourceBytes && importedDigest === sourceHash, 'P15_IMPORTED_DESTINATION_FULL_DOWNLOAD_HASH');
    await page.waitForFunction(() => !document.getElementById('status').dataset.busy);

    // Deliver a new build revision through the real static server. Only its
    // cache identity changes; API/crypto/Worker assertions remain untouched.
    // The generated server file is restored byte-for-byte in finally.
    await action(page, 'new-entry');
    await page.locator('#note-title').fill('PUBLIC P15 update draft');
    await page.locator('#note-body').fill('PUBLIC P15 first durable version');
    await action(page, 'save-local');
    const draft = await page.locator('#drafts li[data-id]').last().getAttribute('data-id');
    // Commit the original immutable request at the real API, then lose only its
    // response. The newer local version and unknown older attempt must both
    // survive activation; the old receipt must not retire the newer draft.
    const noteRoute='https://api.anynote.test:18443/api/v1/threads/*/entries';
    let updateAttempt,updateRequestHash;
    await page.route(noteRoute,async route=>{
      if(route.request().method()==='POST'&&!updateAttempt){
        const body=route.request().postData();
        updateAttempt=JSON.parse(body).bundle.envelope.header.context.operation_id;
        updateRequestHash=createHash('sha256').update(body).digest('hex');
        await commitBeforeLosingResponse(route.request());await route.abort('failed');
      }else await route.continue();
    });
    try{
      await page.locator('#save-note').click();
      await page.waitForFunction(()=>!document.getElementById('status').dataset.busy&&!!document.getElementById('status').dataset.error,null,{timeout:300000});
      check(/^[A-Za-z0-9_-]{22}$/.test(updateAttempt)&&await page.locator('#save-state').getAttribute('data-state')==='SENT_UNKNOWN','P15_UPDATE_STARTS_WITH_REAL_UNKNOWN_IMMUTABLE_ATTEMPT');
    }finally{await page.unroute(noteRoute);}
    let outboxBefore;
    await page.locator('#note-body').fill('PUBLIC P15 latest update draft');
    let updateReceipt;
    const updateReceipts=[];
    const updateReceiptObserver=response=>{
      const u=new URL(response.url());
      if(u.origin==='https://api.anynote.test:18443'&&u.pathname==='/api/v1/me/content-receipts/'+updateAttempt&&response.ok())updateReceipts.push(response.json().then(value=>{updateReceipt=value.receipt;}));
    };
    page.on('response',updateReceiptObserver);
    const match = originalWorker.match(/anynote-p07-static-([a-f0-9]{64})/);
    if (!match) throw Error('P15_BUILD_REVISION_NOT_FOUND');
    const nextRevision = createHash('sha256').update(match[1] + 'public-p15-update').digest('hex');
    writeFileSync(workerPath, originalWorker.replace(match[0], 'anynote-p07-static-' + nextRevision));
    const incoming = page.context().waitForEvent('serviceworker');
    await page.locator('#pwa-help summary').click();
    await page.locator('#pwa-update').click();
    const nextWorker = await incoming;
    await page.waitForFunction(() => document.getElementById('workspace').hidden);
    outboxBefore=await encryptedOutboxHashes();
    check(outboxBefore.length>0,'P15_UNKNOWN_ATTEMPT_HAS_PROTECTED_OUTBOX_RECORD');
    check(await page.locator('#note-body').inputValue() === '', 'P15_UPDATE_MASKS_PLAINTEXT');
    check(await page.locator('#copy-destination option').count() === 0 && await page.locator('#draft-recovery-target option').count() === 0, 'P15_LOCK_CLEARS_DECRYPTED_DESTINATION_TITLES');
    await page.waitForFunction(async () => Boolean((await navigator.serviceWorker.getRegistration('/auth/')).waiting));
    check(await page.evaluate(async () => {
      const r = await navigator.serviceWorker.getRegistration('/auth/');
      return r.active?.state === 'activated' && r.waiting?.state === 'installed';
    }), 'P15_NEW_WORKER_WAITS_FOR_CONTROLLED_WINDOW');
    await page.goto('about:blank');
    const activationDeadline = Date.now() + 30000;
    let activated = false;
    while (Date.now() < activationDeadline) {
      activated = await nextWorker.evaluate(() => self.registration.active?.state === 'activated' && !self.registration.waiting);
      if (activated) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    check(activated, 'P15_ACTUAL_ACTIVATION_AFTER_LAST_WINDOW_CLOSES');
    await page.goto('https://app.anynote.test:18443/auth/notes.html');
    await page.waitForFunction(() => document.getElementById('status').dataset.state === 'ready');
    await readyWriter(page);
    const outboxAfter=await encryptedOutboxHashes();
    check(JSON.stringify(outboxAfter)===JSON.stringify(outboxBefore),'P15_ACTIVATION_PRESERVES_EXACT_ENCRYPTED_OUTBOX_BYTES');
    await page.locator('#phrase').fill(phrase); await action(page, 'unlock');
    await Promise.all(updateReceipts);page.off('response',updateReceiptObserver);
    check(await page.locator('#workspace').isVisible(), 'P15_POST_UPDATE_FRESH_UNLOCK_AND_AUTHORIZATION');
    check(updateReceipt?.operation_id===updateAttempt&&updateReceipt?.status==='COMMITTED','P15_POST_UPDATE_RECONCILES_EXACT_OLD_RECEIPT');
    await page.locator('#drafts li[data-id="' + draft + '"] button').click();
    await page.waitForFunction(() => !document.getElementById('status').dataset.busy);
    check(await page.locator('#note-body').inputValue() === 'PUBLIC P15 latest update draft', 'P15_UPDATE_RETAINS_LATEST_ENCRYPTED_DRAFT');
    check(await page.locator('#save-state').getAttribute('data-state')==='LOCAL_SAVED','P15_OLD_RECEIPT_DOES_NOT_RETIRE_NEWER_DRAFT');
    await page.setViewportSize({width: 1280, height: 900});
    return {
      status: 'PASS', plaintext_bytes: sourceBytes, recovered_bytes: recoveredBytes,
      source_sha256: sourceHash, recovered_sha256: recoveredHash, imported_bytes: importedBytes,
      imported_sha256: importedDigest, mobile_viewport: '390x844; keyboard 390x420',
      updated_attempt_id:updateAttempt,original_update_request_sha256:updateRequestHash,old_receipt_verified_after_update:true,
      retained_outbox_records:outboxBefore.length,outbox_before_after_sha256:createHash('sha256').update(JSON.stringify(outboxBefore)).digest('hex'),
      memory: memory.finish(), process_memory: processes.finish(), v8_memory: await heap.finish(), physical_acceptance: false,
      scope: 'Actual production API/Worker/IndexedDB/OPFS and streaming service-worker download in sandboxed hosted desktop Chromium; not iPhone Files/storage/PRF evidence',
    };
  } finally { memory.abort(); processes.abort(); await heap?.abort(); writeFileSync(workerPath, originalWorker); }
}
