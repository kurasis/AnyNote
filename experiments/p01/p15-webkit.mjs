// Hosted WebKit shell compatibility. No iPhone/Files/passkey/PRF claim.
import {webkit} from 'playwright-core';
import {mkdirSync, writeFileSync, readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {sourceStamp} from '../../scripts/p14-source.mjs';

const root = resolve(import.meta.dirname, '../..'), stamp = sourceStamp(root);
const git = (...args) => execFileSync('git', args, {cwd: root, encoding: 'utf8'}).trim();
const inputs = git('ls-files', '-z').split('\0').filter(p => p && !p.startsWith('docs/evidence/')).map(path => ({
  path, sha256: createHash('sha256').update(readFileSync(resolve(root, path))).digest('hex'),
}));
const report = {purpose: 'P15 actual hosted WebKit install/localization/offline shell',
  status: 'PENDING', physical_acceptance: false, checks: [], inputs, source_tree: git('rev-parse', 'HEAD^{tree}'), ...stamp()};
let browser;
const check = (condition, name) => { if (!condition) throw Error(name); report.checks.push(name); };
try {
  browser = await webkit.launch({headless: true});
  const context = await browser.newContext({viewport: {width: 390, height: 844}});
  const page = await context.newPage(), errors = [];
  page.on('pageerror', () => errors.push('PAGE_ERROR'));
  const response = await page.goto('https://app.anynote.test:18443/auth/notes.html');
  check(response.status() === 200 && response.headers()['content-security-policy'].includes("worker-src 'self'"), 'VERIFIED_TLS_STRICT_CSP');
  await page.locator('#empty').waitFor({state: 'visible'});
  await page.waitForFunction(() => Boolean(navigator.serviceWorker?.controller));
  check(await page.evaluate(() => isSecureContext), 'SECURE_CONTEXT');
  await page.locator('#language').selectOption('ru');
  check(await page.locator('#pwa-help summary').textContent() === 'Установка и хранилище', 'RUSSIAN_INSTALL_GUIDANCE');
  await page.locator('#pwa-help summary').click();
  await page.locator('#pwa-storage').click();
  await page.waitForFunction(() => document.getElementById('pwa-storage-state').textContent.length > 0);
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'MOBILE_HELP_WITHOUT_HORIZONTAL_OVERFLOW');
  const entries = await page.evaluate(async () => {
    const paths = [];
    for (const name of await caches.keys()) for (const request of await (await caches.open(name)).keys()) paths.push(new URL(request.url).pathname);
    return paths;
  });
  check(entries.length === 14 && entries.includes('/auth/manifest.webmanifest'), 'EXACT_STATIC_INSTALL_IN_WEBKIT');
  check(await page.evaluate(async () => (await caches.match('/auth/manifest.webmanifest'))?.headers.get('content-type')?.startsWith('application/manifest+json')), 'REAL_MANIFEST_MEDIA_TYPE');
  await context.setOffline(true);
  await page.reload();
  await page.locator('#empty').waitFor({state: 'visible'});
  check(await page.locator('#unlock-panel').isVisible(), 'OFFLINE_LOCKED_SHELL');
  await context.setOffline(false);
  const returning = page.waitForEvent('load');
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true})));
  await returning; await page.locator('#empty').waitFor({state: 'visible'});
  check(await page.locator('#unlock-panel').isVisible(), 'SYNTHETIC_BFCACHE_SIGNAL_RELOADS_LOCKED_DOCUMENT');
  for (const [path, heading] of [['index.html', 'Вход'], ['devices.html', 'Доверенные устройства и восстановление'], ['vault.html', 'Локальное хранилище устройства']]) {
    await page.goto('https://app.anynote.test:18443/auth/' + path);
    await page.locator('#shell-language').selectOption('ru');
    check((await page.locator('h1,h2').allTextContents()).includes(heading), 'LOCALIZED_' + path.toUpperCase());
    await page.locator('#shell-language').selectOption('en');
    check(await page.evaluate(() => document.documentElement.lang) === 'en', 'ENGLISH_' + path.toUpperCase());
  }
  await page.goBack();
  await page.locator('#shell-language').waitFor({state: 'visible'});
  check(page.url().endsWith('/auth/devices.html') && await page.locator('#unlocked').count() === 1 && await page.locator('#unlocked').isHidden(), 'ACTUAL_HISTORY_RETURN_REQUIRES_LOCAL_UNLOCK');
  check(errors.length === 0, 'NO_RUNTIME_ERRORS');
  report.browser_version = browser.version(); report.status = 'PASS';
  report.scope = 'Actual hosted desktop WebKit shell and offline static worker, no enrolled account or physical iPhone Files/storage/passkey/PRF/memory acceptance';
} catch (error) {
  report.status = 'FAIL'; report.reason = String(error.message).slice(0, 300); process.exitCode = 1;
} finally {
  await browser?.close();
  mkdirSync(root + '/artifacts/p15', {recursive: true});
  writeFileSync(root + '/artifacts/p15/webkit-report.json', JSON.stringify({...report, ...stamp()}, null, 2) + '\n');
  console.log(JSON.stringify({status: report.status, checks: report.checks.length, reason: report.reason,
    browser_version: report.browser_version, physical_acceptance: false}));
}
