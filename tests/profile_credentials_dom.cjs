const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(require('node:path').join(__dirname, '../bridge/static/profile-credentials.js'), 'utf8');

function fixture(clipboard) {
  const field = { type: 'password', value: 'synthetic-disposable-key', focus() { this.focused = true; }, select() { this.selected = true; }, removeAttribute(name) { this.removedAttribute = name; } };
  function control() { return { hidden: true, handlers: {}, attrs: {}, addEventListener(name, handler) { this.handlers[name] = handler; }, setAttribute(name, value) { this.attrs[name] = value; } }; }
  const toggle = control(), copy = control(), status = {textContent: ''};
  const elements = {'.credential-secret': field, '[data-toggle-key]': toggle, '[data-copy-key]': copy, '[data-copy-status]': status};
  const document = {querySelectorAll() { return [{querySelector(selector) { return elements[selector]; }}]; }};
  const pageEvents = {};
  const context = {document, navigator: {clipboard}, window: {addEventListener(event, handler) { pageEvents[event] = handler; }}};
  vm.runInNewContext(source, context);
  return {field, toggle, copy, status, pageEvents};
}

test('masked by default, reversible reveal updates accessible toggle state', () => {
  const f = fixture();
  assert.equal(f.field.type, 'password');
  assert.equal(f.toggle.hidden, false);
  f.toggle.handlers.click();
  assert.equal(f.field.type, 'text');
  assert.equal(f.toggle.attrs['aria-pressed'], 'true');
  assert.equal(f.toggle.textContent, 'Hide key');
  f.toggle.handlers.click();
  assert.equal(f.field.type, 'password');
  assert.equal(f.toggle.attrs['aria-pressed'], 'false');
});

test('leaving the page removes the secret before a back-forward cache can restore it', () => {
  const f = fixture();
  f.toggle.handlers.click();
  f.pageEvents.pagehide();
  assert.equal(f.field.value, '');
  assert.equal(f.field.removedAttribute, 'value');
  assert.equal(f.field.type, 'password');
  assert.equal(f.copy.hidden, true);
  assert.equal(f.toggle.hidden, true);
  assert.match(f.status.textContent, /no longer available/);
});

test('copy is user-triggered and announces success without showing the secret', async () => {
  const writes = [];
  const f = fixture({async writeText(value) { writes.push(value); }});
  assert.deepEqual(writes, []);
  await f.copy.handlers.click();
  assert.deepEqual(writes, ['synthetic-disposable-key']);
  assert.equal(f.field.type, 'password');
  assert.equal(f.status.textContent, 'Key copied.');
});

for (const clipboard of [undefined, {async writeText() { throw new Error('synthetic clipboard denial'); }}]) {
  test('unavailable or denied clipboard preserves a selected key and recovery instructions', async () => {
    const f = fixture(clipboard);
    await f.copy.handlers.click();
    assert.equal(f.field.focused, true);
    assert.equal(f.field.selected, true);
    assert.equal(f.field.type, 'password');
    assert.match(f.status.textContent, /browser’s Copy command/);
    assert.equal(f.status.textContent.includes(f.field.value), false);
  });
}
