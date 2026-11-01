/* Synthetic DOM: execute the shipped script, including its real async handlers. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function browser({ history = false, older = true, ids = [30, 31, 32, 33, 34], paneTop = 0 } = {}) {
  let document;
  const frames = [], timers = new Map(), intervals = [], requests = [], changes = [], revealCalls = [];
  let timerID = 0;
  class Node {
    constructor(name, dataset = {}) {
      this.name = name; this.dataset = dataset; this.children = []; this.listeners = {}; this.attributes = {};
      this.style = {}; this._hidden = false; this._text = ''; this.parent = null;
    }
    get hidden() { return this._hidden; }
    set hidden(value) {
      this._hidden = value;
      if (value && document?.activeElement === this) document.activeElement = body;
    }
    get textContent() { return this._text; }
    set textContent(value) { this._text = value; if (this === status) changes.push(value); }
    get childElementCount() { return this.children.length; }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { return this.children.at(-1) || null; }
    setAttribute(key, value) { this.attributes[key] = value; }
    addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
    dispatch(type, data = {}) {
      for (const fn of this.listeners[type] || []) fn({ target: this, preventDefault() {}, ...data });
    }
    append(...nodes) { this.insert(false, nodes); }
    prepend(...nodes) { this.insert(true, nodes); }
    insert(before, nodes) {
      const flat = nodes.flatMap(node => node.name === 'fragment' ? node.children.splice(0) : [node]);
      for (const node of flat) node.parent = this;
      if (before) this.children.unshift(...flat); else this.children.push(...flat);
    }
    remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); }
    matches(selector) { return selector === 'article[data-message-id][data-sequence][data-thread-id]' && this.name === 'article' && ['messageId', 'sequence', 'threadId'].every(key => key in this.dataset); }
    focus(options = {}) { assert.equal(options.preventScroll, true); document.activeElement = this; }
    scrollIntoView({ block }) {
      revealCalls.push(this);
      const rect = this.getBoundingClientRect();
      if (block === 'start') scroll.scrollTop += rect.top - paneTop;
      else if (rect.top < paneTop) scroll.scrollTop += rect.top - paneTop;
      else if (rect.bottom > paneTop + scroll.clientHeight) scroll.scrollTop += rect.bottom - paneTop - scroll.clientHeight;
    }
    getBoundingClientRect() {
      let top = paneTop, height = 20;
      if (this === scroll) height = scroll.clientHeight;
      else if (this.name === 'article') { top = paneTop + historyHeight() + messages.children.indexOf(this) * 100 - scroll.scrollTop; height = 100; }
      else if (this === olderControl || this === signIn) { top = paneTop + 12 - scroll.scrollTop; height = this === olderControl ? 40 : 20; }
      return { top, bottom: top + height, height };
    }
  }
  const body = new Node('body'), page = new Node('section', { threadId: 'synthetic-thread', olderUrl: older ? '/conversation/messages?thread_id=synthetic-thread&cursor=older-30' : '', newerUrl: '/conversation/messages?thread_id=synthetic-thread&cursor=newer-34' });
  const messages = new Node('messages'), scroll = new Node('scroll'), olderControl = new Node('older'), historyStatus = new Node('history'), signIn = new Node('signIn'), status = new Node('status'), jump = new Node('jump'), check = new Node('check'), back = new Node('back');
  const elements = { 'data-owner-conversation': page, 'data-message-scroll': scroll, 'data-messages': messages, 'data-load-older': olderControl, 'data-history-status': historyStatus, 'data-sign-in': signIn, 'data-conversation-status': status, 'data-jump-latest': jump, 'data-check-new': check, 'data-back-list': back };
  page.querySelector = selector => elements[selector.slice(1, -1)] || null;
  document = { activeElement: body, hidden: false, querySelector: page.querySelector, listeners: {}, addEventListener: Node.prototype.addEventListener, dispatch: Node.prototype.dispatch,
    createDocumentFragment: () => new Node('fragment'), createElement(name) {
      assert.equal(name, 'template'); const template = { content: new Node('fragment') };
      Object.defineProperty(template, 'innerHTML', { set(html) {
        const articles = [...html.matchAll(/<article data-message-id="([^"]+)" data-sequence="([^"]+)" data-thread-id="([^"]+)"><\/article>/g)];
        for (const match of articles) template.content.append(new Node('article', { messageId: match[1], sequence: match[2], threadId: match[3] }));
        if (html && !articles.length) template.content.append(new Node('invalid'));
      }}); return template;
    }
  };
  const historyHeight = () => 24 + (olderControl.hidden ? 0 : 40) + (historyStatus.hidden ? 0 : 20) + (signIn.hidden ? 0 : 20);
  let top = 0;
  Object.defineProperties(scroll, {
    clientHeight: { get: () => parseFloat(scroll.style.height) || 300 },
    scrollHeight: { get: () => historyHeight() + messages.children.length * 100 },
    scrollTop: { get: () => top, set: value => { top = Math.min(Math.max(0, value), Math.max(0, scroll.scrollHeight - scroll.clientHeight)); } }
  });
  for (const id of ids) messages.append(new Node('article', { messageId: `m${id}`, sequence: String(id), threadId: 'synthetic-thread' }));
  signIn.hidden = true; jump.hidden = true; status.textContent = 'Latest messages';
  const location = { href: `https://bridge.example.com/conversation?thread_id=synthetic-thread${history ? '&cursor=history' : ''}`, origin: 'https://bridge.example.com', pathname: '/conversation', search: '?thread_id=synthetic-thread', assign(url) { this.assigned = url; } };
  const window = { innerHeight: paneTop + 388, listeners: {}, addEventListener: Node.prototype.addEventListener, dispatch: Node.prototype.dispatch };
  const context = { document, location, window, URL, AbortController, Map, Set, sessionStorage: { getItem: () => null }, requestAnimationFrame: fn => frames.push(fn),
    setTimeout(fn, delay) { const id = ++timerID; timers.set(id, { fn, delay }); return id; }, clearTimeout: id => timers.delete(id), setInterval: (fn, delay) => intervals.push({ fn, delay }),
    fetch(url, options) { return new Promise((resolve, reject) => { requests.push({ url, options, resolve, reject }); options.signal.addEventListener('abort', () => reject(new Error('aborted'))); }); }
  };
  vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), context);
  function render() { while (frames.length) frames.splice(0).forEach(fn => fn()); }
  async function settle() { await new Promise(resolve => setImmediate(resolve)); render(); await new Promise(resolve => setImmediate(resolve)); render(); }
  function response(index, messageIDs = [], { olderURL = '/conversation/messages?thread_id=synthetic-thread&cursor=older-next', newerURL = '/conversation/messages?thread_id=synthetic-thread&cursor=newer-next', more = false, code = 200, html } = {}) {
    requests[index].resolve({ status: code, ok: code === 200, headers: { get: () => 'application/json' }, json: async () => ({ html: html ?? messageIDs.map(id => `<article data-message-id="m${id}" data-sequence="${id}" data-thread-id="synthetic-thread"></article>`).join(''), older_url: olderURL, newer_url: newerURL, has_more: more }) });
  }
  function timersAt(delay) { for (const [id, timer] of [...timers]) if (timer.delay === delay) { timers.delete(id); timer.fn(); } }
  function move(value) { scroll.scrollTop = value; scroll.dispatch('scroll'); }
  render(); changes.length = 0;
  return { document, window, scroll, messages, olderControl, historyStatus, signIn, status, jump, check, changes, requests, intervals, timers, revealCalls, render, settle, response, timersAt, move };
}

const cases = {
  async arrivals() {
    const b = browser();
    assert.equal(b.intervals[0].delay, 15000);
    for (let index = 0; index < 2; index++) {
      b.intervals[0].fn(); b.response(index, [35 + index]); await b.settle();
      assert.equal(b.status.textContent, '1 new message received.');
      assert.equal(b.scroll.scrollTop, b.scroll.scrollHeight - b.scroll.clientHeight);
    }
    assert.equal(b.changes.filter(value => value === '1 new message received.').length, 2);
    b.intervals[0].fn(); b.response(2, [36]); await b.settle();
    assert.equal(b.messages.children.filter(node => node.dataset.messageId === 'm36').length, 1);
    assert.equal(b.changes.filter(value => value === '1 new message received.').length, 2);
  },
  async unread() {
    const b = browser(); b.move(120);
    for (let i = 0; i < 2; i++) {
      b.intervals[0].fn(); b.response(i, [35 + i]); await b.settle();
      assert.equal(b.status.textContent, 'New messages available.'); assert.equal(b.scroll.scrollTop, 120);
    }
    assert.equal(b.changes.filter(value => value === 'New messages available.').length, 2);
    b.check.dispatch('click'); b.response(2, []); await b.settle();
    assert.equal(b.status.textContent, 'New messages available.', 'an empty check must not clear unread feedback');
    b.jump.focus({ preventScroll: true }); b.move(b.scroll.scrollHeight);
    b.render(); assert.equal(b.status.textContent, 'Latest messages'); assert.equal(b.jump.hidden, true); assert.equal(b.document.activeElement, b.scroll);
  },
  async keyboard() {
    const b = browser({ paneTop: 216 });
    b.olderControl.focus({ preventScroll: true }); b.move(0);
    assert.equal(b.requests.length, 0, 'focusing history must not load it');
    b.olderControl.dispatch('click', { detail: 0 });
    b.response(0, [28, 29]); await b.settle();
    const first = b.messages.firstElementChild;
    assert.equal(b.document.activeElement, first); assert.equal(first.dataset.messageId, 'm28');
    assert.equal(first.attributes.tabindex, '-1'); assert.equal(first.getBoundingClientRect().top, 228);
    assert.equal(b.scroll.getBoundingClientRect().top, 216);
    assert.equal(b.revealCalls.length, 0, 'keyboard reveal must only change pane scrollTop');
    b.olderControl.focus({ preventScroll: true }); b.move(0); assert.equal(b.requests.length, 1);
    b.olderControl.dispatch('click', { detail: 0 }); b.response(1, [26, 27], { olderURL: null }); await b.settle();
    assert.equal(b.olderControl.hidden, true); assert.equal(b.document.activeElement.dataset.messageId, 'm26');
    assert.equal(b.document.activeElement.getBoundingClientRect().top, 228);
    assert.equal(b.scroll.getBoundingClientRect().top, 216);
    assert.equal(b.revealCalls.length, 0);
  },
  async focus() {
    const b = browser(); b.move(120); b.jump.focus({ preventScroll: true }); b.jump.dispatch('click'); await b.settle();
    assert.equal(b.jump.hidden, true); assert.equal(b.document.activeElement, b.messages.lastElementChild);
    b.check.focus({ preventScroll: true }); b.check.dispatch('click'); b.response(0, [], { code: 401 }); await b.settle();
    assert.equal(b.check.hidden, true); assert.equal(b.document.activeElement, b.signIn); assert.equal(b.signIn.hidden, false);
    assert.ok(b.signIn.getBoundingClientRect().top >= 0);
    const c = browser(); c.olderControl.focus({ preventScroll: true }); c.olderControl.dispatch('click', { detail: 1 });
    c.response(0, [28, 29], { olderURL: null }); await c.settle();
    assert.equal(c.document.activeElement, c.scroll);
    const d = browser(); d.move(40);
    d.olderControl.focus({ preventScroll: true }); d.move(0);
    d.response(0, [28, 29]); await d.settle();
    assert.equal(d.document.activeElement, d.olderControl, 'automatic load must retain focus');
    assert.equal(d.olderControl.getBoundingClientRect().top, 12, 'focused control remains visible');
  },
  async expired_focus() {
    const b = browser(); b.check.focus({ preventScroll: true }); b.check.dispatch('click');
    b.response(0, [], { code: 401 }); await b.settle();
    assert.equal(b.document.activeElement, b.signIn); assert.equal(b.signIn.hidden, false);
    assert.ok(b.signIn.getBoundingClientRect().top >= 0);
  },
  async last_older_focus() {
    const b = browser(); b.olderControl.focus({ preventScroll: true });
    b.olderControl.dispatch('click', { detail: 0 }); b.response(0, [29], { olderURL: null }); await b.settle();
    assert.equal(b.olderControl.hidden, true); assert.equal(b.document.activeElement.dataset.messageId, 'm29');
    assert.equal(b.document.activeElement.getBoundingClientRect().top, 12);
  },
  async anchor() {
    const b = browser(); b.move(40); assert.equal(b.requests.length, 1);
    // Read a different message while the response is in flight.
    b.move(160); const held = b.messages.children[1], before = held.getBoundingClientRect().top;
    b.response(0, [27, 28, 29], { olderURL: null }); await b.settle();
    assert.equal(held.getBoundingClientRect().top, before, 'final control height belongs inside compensation');
    assert.equal(b.document.activeElement.name, 'body');
    assert.equal(b.requests.length, 1, 'compensation must not load another page');
    assert.equal(b.historyStatus.hidden, false);
    const c = browser(); c.move(120); c.olderControl.focus({ preventScroll: true });
    const pointerHeld = c.messages.children[1], pointerBefore = pointerHeld.getBoundingClientRect().top;
    c.olderControl.dispatch('click', { detail: 1 }); c.response(0, [28, 29]); await c.settle();
    assert.equal(pointerHeld.getBoundingClientRect().top, pointerBefore);
    assert.equal(c.document.activeElement, c.scroll);
  },
  async older_feedback() {
    const b = browser();
    for (let i = 0; i < 2; i++) {
      b.olderControl.dispatch('click', { detail: 1 }); b.response(i, [29 - i]); await b.settle();
      assert.equal(b.status.textContent, 'Older messages loaded.');
    }
    assert.equal(b.changes.filter(value => value === 'Older messages loaded.').length, 2);
    b.olderControl.dispatch('click', { detail: 1 }); b.response(2, [], { code: 503 }); await b.settle();
    assert.equal(b.historyStatus.hidden, false); assert.match(b.historyStatus.textContent, /Couldn’t load/);
    b.olderControl.dispatch('click', { detail: 1 });
    assert.equal(b.historyStatus.hidden, true);
    b.response(3, [26]); await b.settle(); assert.equal(b.historyStatus.hidden, true);
  },
  async older_error() {
    const b = browser(); b.olderControl.dispatch('click', { detail: 1 });
    b.response(0, [], { code: 503 }); await b.settle();
    assert.equal(b.historyStatus.hidden, false); assert.match(b.historyStatus.textContent, /Couldn’t load/);
    b.olderControl.dispatch('click', { detail: 1 });
    assert.equal(b.historyStatus.hidden, true); b.response(1, [29]); await b.settle();
    assert.equal(b.historyStatus.hidden, true);
  },
  async timeout_races() {
    const b = browser(); b.olderControl.dispatch('click', { detail: 1 });
    assert.ok([...b.timers.values()].some(timer => timer.delay === 20000));
    b.timersAt(20000); await b.settle(); assert.equal(b.historyStatus.hidden, false);
    b.olderControl.dispatch('click', { detail: 1 }); b.response(1, [29]); await b.settle();
    assert.equal(b.messages.children[0].dataset.messageId, 'm29');
    b.intervals[0].fn(); b.intervals[0].fn(); assert.equal(b.requests.length, 3, 'one newer request at a time');
    b.response(2, [35], { more: true }); await b.settle(); b.timersAt(0);
    assert.equal(b.requests.length, 4); b.response(3, [35, 36]); await b.settle();
    assert.equal(b.messages.children.filter(n => n.dataset.messageId === 'm35').length, 1);
    assert.match(b.requests[3].url, /newer-next/);
    b.intervals[0].fn(); b.window.dispatch('pagehide'); b.response(4, [37]); await b.settle();
    assert.equal(b.messages.children.some(n => n.dataset.messageId === 'm37'), false);
    const c = browser(); c.intervals[0].fn(); c.olderControl.dispatch('click', { detail: 1 });
    c.response(1, [], { code: 401 }); await c.settle(); c.response(0, [35]); await c.settle();
    assert.equal(c.messages.children.some(n => n.dataset.messageId === 'm35'), false);
    assert.match(c.status.textContent, /session ended/);
    const d = browser(); d.intervals[0].fn(); d.olderControl.dispatch('click', { detail: 1 });
    d.response(0, [], { code: 401 }); await d.settle(); d.requests[1].reject(new Error('offline')); await d.settle();
    assert.match(d.status.textContent, /session ended/, 'late errors must not replace sign-in recovery');
  }
};
(async () => { await cases[process.argv[3]](); process.stdout.write(`${process.argv[3]} passed\n`); })().catch(error => { console.error(error); process.exitCode = 1; });
