// These execute the actual worker handlers with host APIs modeled explicitly.
// They prove caching/update policy, not physical browser or iPhone behavior.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
import {storageDescription} from './pwa.mjs';

function worker({fail} = {}) {
  const listeners = new Map(), stores = new Map(), fetched = [], deleted = [];
  let claimed = 0;
  const notifications = [], opened = [];
  const self = {
    location: {origin: 'https://app.anynote.test'},
    clients: {claim: async () => { claimed++; }, matchAll: async () => [], openWindow: async url => opened.push(url)},
    registration: {scope: 'https://app.anynote.test/auth/', showNotification: async (...args) => notifications.push(args)},
    addEventListener: (name, handler) => listeners.set(name, handler),
  };
  class Request {
    constructor(path, options) { this.url = path; this.options = options; }
  }
  const caches = {
    async open(name) {
      if (!stores.has(name)) stores.set(name, new Map());
      return {put: async (path, response) => stores.get(name).set(path, response)};
    },
    keys: async () => [...stores.keys()],
    delete: async name => { deleted.push(name); return stores.delete(name); },
    match: async (path, {cacheName}) => stores.get(cacheName)?.get(path),
  };
  // export-worker.mjs has separate integration tests; this harness exercises
  // static install/fetch/activation and cannot synthesize export success.
  const source = readFileSync(new URL('../vault-web/sw.mjs', import.meta.url), 'utf8').replace("import './export-worker.mjs';", '');
  vm.runInNewContext(source, {
    self, caches, URL, Request, ANYNOTE_STATIC_REVISION: 'new-revision',
    fetch: async request => {
      fetched.push(request);
      return {ok: request.url !== fail, type: 'basic', url: request.url};
    },
  });
  const lifecycle = name => {
    let result;
    listeners.get(name)({waitUntil: promise => { result = promise; }});
    return result;
  };
  return {self, stores, caches, fetched, deleted, lifecycle, notifications, opened, claimed: () => claimed,
    event(name, data) {
      let result;
      listeners.get(name)({...data, waitUntil: promise => { result = promise; }});
      return result;
    },
    request(url, method = 'GET') {
      let response;
      listeners.get('fetch')({request: {url, method}, respondWith: value => { response = value; }});
      return response;
    },
  };
}

test('installation fetches only enumerated public assets, without cookies or redirects', async () => {
  const w = worker(); await w.lifecycle('install');
  assert.equal(w.fetched.length, 14);
  for (const request of w.fetched) {
    assert.equal(request.options.credentials, 'omit');
    assert.equal(request.options.redirect, 'error');
    assert.equal(request.options.cache, 'reload');
    assert.match(request.url, /^\/auth\/[a-z0-9.-]+$/);
  }
  assert.equal(typeof w.self.skipWaiting, 'undefined');
  assert.equal(w.claimed(), 0);
});

test('failed install discards only its incomplete candidate and preserves prior caches', async () => {
  const w = worker({fail: '/auth/vault-worker.js'});
  w.stores.set('anynote-p07-static-old', new Map([['protected-old-shell', true]]));
  w.stores.set('unrelated-cache', new Map());
  await assert.rejects(w.lifecycle('install'), /STATIC_INSTALL_FAILED/);
  assert.deepEqual(w.deleted, ['anynote-p07-static-new-revision']);
  assert.equal(w.stores.get('anynote-p07-static-old').get('protected-old-shell'), true);
  assert.equal(w.stores.has('unrelated-cache'), true);
});

test('API/auth responses, export routes, query strings and foreign origins never enter static cache', async () => {
  const w = worker(); await w.lifecycle('install');
  for (const path of ['/api/v1/auth/csrf', '/auth/file-export/secret', '/auth/notes.js?private=value', '/auth/unknown.js']) {
    assert.equal(w.request('https://app.anynote.test' + path), undefined);
  }
  assert.equal(w.request('https://api.anynote.test/auth/notes.js'), undefined);
  assert.equal(w.request('https://app.anynote.test/auth/notes.js', 'POST'), undefined);
  assert.equal((await w.request('https://app.anynote.test/auth/notes.js')).url, '/auth/notes.js');
});

test('activation retains unrelated stores; there is no early activation message handler', async () => {
  const w = worker(); await w.lifecycle('install');
  w.stores.set('anynote-p07-static-old', new Map());
  w.stores.set('ciphertext-cache', new Map([['opaque-frame', true]]));
  await w.lifecycle('activate');
  assert.equal(w.claimed(), 1);
  assert.equal(w.stores.has('anynote-p07-static-old'), false);
  assert.equal(w.stores.get('ciphertext-cache').get('opaque-frame'), true);
});

test('storage guidance distinguishes unknown estimates from known zero capacity', () => {
  const text = {estimate: 'usage / quota', unknown: 'unknown'};
  assert.equal(storageDescription({usage: 0, quota: 0}, text), 'usage / quota: 0 / 0 bytes');
  assert.equal(storageDescription({usage: NaN, quota: -1}, text), 'usage / quota: unknown / unknown bytes');
  assert.equal(storageDescription(undefined, text), 'usage / quota: unknown / unknown bytes');
});

test('push ignores hostile payloads and notification clicks open only the locked app entrypoint', async () => {
  const w = worker();
  await w.event('push', {data: {json() { throw Error('PAYLOAD_MUST_NOT_BE_READ'); }}});
  assert.equal(w.notifications[0][0], 'AnyNote');
  assert.equal(w.notifications[0][1].body, 'New activity in your vault.');
  assert.equal(Object.hasOwn(w.notifications[0][1], 'data'), false);
  let closed = false;
  await w.event('notificationclick', {notification: {close() { closed = true; }, data: {url: 'https://hostile.invalid/'}}});
  assert.equal(closed, true);
  assert.deepEqual(w.opened, ['https://app.anynote.test/auth/notes.html']);
});
