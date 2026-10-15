import test from 'node:test';
import assert from 'node:assert/strict';
import {createLocalizer} from './localize.mjs';

test('language changes never replace later runtime/recovery text with initial UI labels', () => {
  const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const originalDocument = globalThis.document;
  const label = {nodeType: 3, textContent: 'Ready', isConnected: true};
  const runtime = {nodeType: 3, textContent: '', isConnected: true};
  let selector;
  Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {language: 'ru'}});
  globalThis.document = {
    documentElement: {},
    querySelectorAll: () => [{childNodes: [label]}, {childNodes: [runtime]}],
    querySelector: () => ({prepend() {}}),
    createElement: tag => {
      const node = {append() {}};
      if (tag === 'select') selector = node;
      return node;
    },
  };
  try {
    const locale = createLocalizer();
    assert.equal(label.textContent, 'Готово');
    runtime.textContent = 'Ready';
    selector.value = 'en'; selector.onchange();
    selector.value = 'ru'; selector.onchange();
    assert.equal(runtime.textContent, 'Ready');
    assert.equal(locale.text('constructor'), 'constructor');
    assert.equal(locale.text('__proto__'), '__proto__');
    const fingerprint = 'PUBLIC-{}-UNCHANGED-<value>';
    assert.equal(locale.template(['Account ', ': ', ''], fingerprint, 'restricted'),
      'Аккаунт ' + fingerprint + ': restricted');
    label.textContent = 'PUBLIC runtime output';
    selector.value = 'en'; selector.onchange();
    assert.equal(label.textContent, 'PUBLIC runtime output');
  } finally {
    if (originalNavigator) Object.defineProperty(globalThis, 'navigator', originalNavigator);
    else delete globalThis.navigator;
    if (originalDocument === undefined) delete globalThis.document;
    else globalThis.document = originalDocument;
  }
});
