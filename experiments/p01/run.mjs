// Runs real native/Node/browser-worker adapters. No production data or service.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { chromium } from 'playwright-core';
import { emitFixture, verifyFixture, sodium } from './crypto.mjs';
import './build.mjs';
import { checkLocalUnlock } from './unlock-checks.mjs';
import { serve } from './transport.mjs';
import { checkSelectedFiles } from './physical-checks.mjs';
import { sampleRss } from './memory.mjs';

const large = process.argv.includes('--large');
const updateFixtures = process.argv.includes('--write-fixtures');
const nativeOnly = process.argv.includes('--native-only');
const native = resolve('native/target/release', process.platform === 'win32' ? 'anynote-p01.exe' : 'anynote-p01');
const scratch = await mkdtemp(join(tmpdir(), 'anynote-p01-'));
const results = { experiment: 'P01-CRYPTO-INTEROP', date: new Date().toISOString(),
  node: process.version, platform: `${process.platform}/${process.arch}`, large, native_only: nativeOnly,
  primitive_checks: [], native_files: [], browser_files: [], limitations: [
    'Primitive-only synthetic fixtures, not a frozen/reviewed application protocol.',
    'Chromium on the host is not iPhone, Windows WebView2 or Hello evidence.',
    'Loopback transfer is not Laravel authorization, resume, recovery, durable publication or iOS Files export.'
  ] };

function nativeJson(args, input) {
  return JSON.parse(execFileSync(native, args, { input: input === undefined ? undefined : JSON.stringify(input),
    encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 300000 }));
}
function passed(result, label) {
  assert.equal(result.status, 'PASS');
  assert.equal(result.checks.length, 39, 'All intended primitive checks must execute');
  assert.equal(new Set(result.checks).size, 39);
  results.primitive_checks.push({ direction: label, count: result.checks.length, sodium_version: result.sodium_version });
  console.log(`PASS: ${label}: ${result.checks.length} positive/negative checks`);
}

async function executable() {
  const candidates = [process.env.CHROMIUM_EXECUTABLE,
    '/usr/bin/chromium', '/usr/bin/google-chrome', '/usr/bin/chromium-browser',
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].filter(Boolean);
  for (const path of candidates) { try { await access(path); return path; } catch {} }
  throw new Error('A real Chromium/Chrome executable is required; set CHROMIUM_EXECUTABLE');
}

let transport, browser, context;
try {
  await sodium.ready;
  const rust = nativeJson(['emit']);
  passed(nativeJson(['verify'], rust), 'Rust -> Rust');
  passed(await verifyFixture(rust), 'Rust -> Node');
  const node = await emitFixture('node');
  passed(nativeJson(['verify'], node), 'Node -> Rust');
  passed(await verifyFixture(node), 'Node -> Node');
  const changed = structuredClone(rust);
  const changedFirstByte = (Number.parseInt(changed.aead[0].ciphertext.slice(0, 2), 16) ^ 1).toString(16).padStart(2, '0');
  changed.aead[0].ciphertext = changedFirstByte + changed.aead[0].ciphertext.slice(2);
  const rejected = spawnSync(native, ['verify'], { input: JSON.stringify(changed), encoding: 'utf8' });
  assert.equal(rejected.status, 1, 'Rust must reject corrupted fixture, preserving nonzero exit');
  await assert.rejects(verifyFixture(changed));
  const unknown = structuredClone(rust); unknown.fixture_version = 99;
  assert.equal(spawnSync(native, ['verify'], { input: JSON.stringify(unknown) }).status, 1);
  await assert.rejects(verifyFixture(unknown));

  for (const length of [0, 1, 8388607, 8388608, 8388609, ...(large ? [1000000000] : [])]) {
    const directory = join(scratch, `native-${length}`);
    const result = nativeJson(['file-roundtrip', directory, String(length)]);
    assert.equal(result.plaintext_bytes, length);
    assert.equal(result.chunks, Math.ceil(length / 8388608));
    assert.equal(result.ciphertext_bytes, length + result.chunks * 16);
    results.native_files.push(result); await rm(directory, { recursive: true });
    console.log(`PASS: native real file ${length} bytes; peak RSS ${result.peak_rss_kib} KiB`);
  }
  const oversizePath = join(scratch, 'oversize-must-not-exist');
  assert.equal(spawnSync(native, ['file-roundtrip', oversizePath, '1000000001']).status, 1);
  await assert.rejects(access(oversizePath));

  if (nativeOnly) {
    results.local_unlock = await checkLocalUnlock(native, null);
    if (updateFixtures) {
      await mkdir('fixtures', { recursive: true });
      for (const [name, fixture] of [['rust', rust], ['node', node]]) {
        await writeFile(`fixtures/${name}.json`, JSON.stringify(fixture, null, 2) + '\n');
      }
    } else {
      for (const name of ['rust', 'node', 'browser-worker']) {
        const fixture = JSON.parse(await readFile(`fixtures/${name}.json`, 'utf8'));
        passed(nativeJson(['verify'], fixture), `committed ${name} fixture -> Rust`);
        passed(await verifyFixture(fixture), `committed ${name} fixture -> Node`);
      }
    }
    results.status = 'PASS_NATIVE_BROWSER_NOT_RUN';
    await mkdir('artifacts', { recursive: true });
    await writeFile(`artifacts/native-${large ? 'large' : 'small'}-report.json`, JSON.stringify(results, null, 2) + '\n');
    console.log('PASS: native/Node slice; browser not run in this invocation');
  } else {

  transport = await serve({ scratch });
  const externalRequests = [], pageErrors = [];
  // Keep Chromium's sandbox enabled. Any container-specific exception requires
  // an explicitly isolated runner override documented in the resulting evidence.
  context = await chromium.launchPersistentContext(join(scratch, 'browser-profile'),
    { executablePath: await executable(), headless: true, chromiumSandbox: true });
  browser = context.browser();
  assert(browser, 'Persistent Chromium must expose its browser connection');
  results.browser_version = browser.version();
  results.browser_storage_mode = 'isolated temporary disk-backed persistent profile; not incognito';
  // Do not intercept binary PUT bodies through CDP: it creates large artificial
  // copies and distorts the bounded-transfer experiment. CSP restricts all
  // script/worker/connect sources to this origin; observe URLs without body reads.
  context.on('request', (request) => {
    if (new URL(request.url()).origin !== transport.origin) externalRequests.push(request.url());
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto(transport.origin);
  await page.waitForFunction(() => typeof globalThis.p01 === 'function');
  assert.equal(await page.evaluate(() => globalThis.crossOriginIsolated), true);
  const fromRust = await page.evaluate((fixture) => globalThis.p01({ kind: 'interop', fixture }), rust);
  passed(fromRust.checks, 'Rust -> Chromium worker');
  const fromNode = await page.evaluate((fixture) => globalThis.p01({ kind: 'interop', fixture }), node);
  passed(fromNode.checks, 'Node -> Chromium worker');
  const worker = fromRust.fixture;
  passed(nativeJson(['verify'], worker), 'Chromium worker -> Rust');
  passed(await verifyFixture(worker), 'Chromium worker -> Node');
  await assert.rejects(page.evaluate((fixture) => globalThis.p01({ kind: 'interop', fixture }), changed));
  await assert.rejects(page.evaluate((fixture) => globalThis.p01({ kind: 'interop', fixture }), unknown));
  results.fixture_rejection_checks = 6;
  const cdp = await browser.newBrowserCDPSession();
  for (const length of [0, 1, 8388607, 8388608, 8388609, ...(large ? [1000000000] : [])]) {
    await transport.reset();
    let peak = await sampleRss(cdp); const baseline = peak;
    let sampling = false;
    const interval = setInterval(async () => {
      if (sampling) return; sampling = true;
      try { const current = await sampleRss(cdp); if (current !== null) peak = Math.max(peak ?? 0, current); }
      catch {} finally { sampling = false; }
    }, 25);
    let response;
    try { response = await page.evaluate((size) => globalThis.p01({ kind: 'roundtrip', length: size }), length); }
    finally { clearInterval(interval); }
    const result = response.result;
    const expected = length + Math.ceil(length / 8388608) * 16;
    assert.equal(result.plaintext_bytes, length); assert.equal(result.ciphertext_bytes, expected);
    assert.equal(transport.counts().uploaded_bytes, expected); assert.equal(transport.counts().downloaded_bytes, expected);
    results.browser_files.push({ ...result, ...transport.counts(), baseline_aggregate_rss_kib: baseline,
      sampled_peak_aggregate_rss_kib: peak, sampled_increment_rss_kib: baseline === null || peak === null ? null : peak - baseline,
      memory_method: '25ms CDP process enumeration + Linux /proc RSS; shared pages may count twice; transient peaks may be missed' });
    console.log(`PASS: Chromium worker transfer ${length} bytes; aggregate RSS increment ${baseline === null ? 'unavailable' : peak - baseline} KiB`);
  }
  await assert.rejects(page.evaluate(() => globalThis.p01({ kind: 'roundtrip', length: 1000000001 })));
  assert.equal(externalRequests.length, 0, 'No remote scripts/helpers or requests permitted');
  assert.equal(pageErrors.length, 0, 'No hidden browser errors');
  results.external_requests = externalRequests.length;
  results.oversize_rejections = 2;

  if (updateFixtures) {
    await mkdir('fixtures', { recursive: true });
    for (const [name, fixture] of [['rust', rust], ['node', node], ['browser-worker', worker]]) {
      await writeFile(`fixtures/${name}.json`, JSON.stringify(fixture, null, 2) + '\n');
    }
  } else {
    for (const name of ['rust', 'node', 'browser-worker']) {
      const fixture = JSON.parse(await readFile(`fixtures/${name}.json`, 'utf8'));
      passed(nativeJson(['verify'], fixture), `committed ${name} fixture -> Rust`);
      passed(await verifyFixture(fixture), `committed ${name} fixture -> Node`);
      passed((await page.evaluate((data) => globalThis.p01({ kind: 'interop', fixture: data }), fixture)).checks, `committed ${name} fixture -> Chromium worker`);
    }
  }
  results.local_unlock = await checkLocalUnlock(native, page);
  results.selected_file_export = await checkSelectedFiles(page, transport, scratch, large, cdp);
  assert.equal(externalRequests.length, 0, 'No external requests including the physical trial page');
  assert.equal(pageErrors.length, 0, 'No hidden browser errors including the physical trial page');
  results.status = 'PASS';
  await mkdir('artifacts', { recursive: true });
  await writeFile(`artifacts/${large ? 'large' : 'small'}-report.json`, JSON.stringify(results, null, 2) + '\n');
  console.log(`PASS: P01 slice; ${results.primitive_checks.reduce((n, c) => n + c.count, 0)} primitive checks; report written`);
  }
} catch (error) {
  results.status = 'FAIL'; results.error = String(error.message);
  await mkdir('artifacts', { recursive: true });
  await writeFile('artifacts/failure-report.json', JSON.stringify(results, null, 2) + '\n');
  throw error;
} finally {
  if (context) await context.close(); else await browser?.close();
  if (transport) await new Promise((done) => transport.server.close(done));
  await rm(scratch, { recursive: true, force: true });
}
