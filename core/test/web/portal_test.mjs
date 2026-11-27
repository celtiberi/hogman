import assert from 'node:assert/strict';
import test from 'node:test';

import { createApiClient } from '../../portal/js/api.js';
import { renderBillingBanner, renderPenDelete } from '../../portal/js/billing.js';
import { createPressTwice, formatUTCDate, formatUTCTime, relativeTime } from '../../portal/js/dom.js';

class FakeClassList {
  constructor() {
    this.set = new Set();
  }
  add(c) { this.set.add(c); }
  remove(c) { this.set.delete(c); }
  contains(c) { return this.set.has(c); }
  toggle(c, force) {
    if (force === undefined) {
      if (this.set.has(c)) this.set.delete(c);
      else this.set.add(c);
    } else if (force) {
      this.set.add(c);
    } else {
      this.set.delete(c);
    }
  }
}

class FakeNode {
  constructor(tag, id = '') {
    this.tag = tag;
    this.id = id;
    this.type = '';
    this.className = '';
    this.classList = new FakeClassList();
    this.hidden = false;
    this.disabled = false;
    this.isConnected = true;
    this.value = '';
    this.placeholder = '';
    this.textContent = '';
    this.children = [];
    this.onclick = null;
    this.oninput = null;
    this.onsubmit = null;
  }
  append(...nodes) {
    this.children.push(...nodes);
  }
  replaceChildren(...nodes) {
    this.children = [...nodes];
  }
  focus() {}
}

function makeFakeDoc(ids = []) {
  const byId = Object.fromEntries(ids.map(id => [id, new FakeNode('div', id)]));
  return {
    byId,
    doc: {
      getElementById: id => byId[id] || null,
      createElement: tag => new FakeNode(tag),
      createTextNode: text => ({ textContent: String(text) }),
    },
  };
}

function findButton(root, label) {
  if (root.tag === 'button' && root.textContent === label) return root;
  for (const child of root.children || []) {
    const found = findButton(child, label);
    if (found) return found;
  }
  return null;
}

test('createApiClient sends no-store JSON requests and extracts server or HTTP errors', async () => {
  const calls = [];
  const api = createApiClient(async (url, opts) => {
    calls.push([url, opts]);
    if (url === '/api/ok') {
      return { ok: true, status: 200, async json() { return { hello: 'world' }; } };
    }
    if (url === '/api/err-msg') {
      return { ok: false, status: 403, async json() { return { error: 'admins only' }; } };
    }
    return { ok: false, status: 502, async json() { throw new Error('not json'); } };
  });

  const ok = await api('POST', '/ok', { a: 1 });
  assert.deepEqual(ok, { hello: 'world' });
  assert.equal(calls[0][0], '/api/ok');
  assert.equal(calls[0][1].cache, 'no-store');
  assert.equal(calls[0][1].headers['Content-Type'], 'application/json');
  assert.equal(calls[0][1].body, '{"a":1}');

  await assert.rejects(() => api('GET', '/err-msg'), /admins only/);
  await assert.rejects(() => api('GET', '/err-bad-json'), /HTTP 502/);
});

test('pressTwice requires same connected button, restores label on 2nd click/expiry, and rejects stale re-rendered buttons', () => {
  const timers = new Map();
  let nextId = 1;
  const pressTwice = createPressTwice({
    setTimer(fn) {
      const id = nextId++;
      timers.set(id, fn);
      return id;
    },
    clearTimer(id) {
      timers.delete(id);
    },
  });

  const btn1 = new FakeNode('button');
  btn1.textContent = 'Remove';

  // 1st click arms and changes text.
  assert.equal(pressTwice('dev1', btn1, 'Remove laptop?'), false);
  assert.equal(btn1.textContent, 'Remove laptop?');
  assert.equal(btn1.classList.contains('armed'), true);

  // 2nd click on same connected button restores original label and fires.
  assert.equal(pressTwice('dev1', btn1, 'Remove laptop?'), true);
  assert.equal(btn1.textContent, 'Remove');
  assert.equal(btn1.classList.contains('armed'), false);
  assert.equal(timers.size, 0);

  // Arm btn1, then simulate DOM re-render producing a fresh btn2 with the same key:
  // clicking btn2 must re-arm rather than firing destructively on its 1st click.
  assert.equal(pressTwice('dev1', btn1, 'Remove laptop?'), false);
  btn1.isConnected = false;
  const btn2 = new FakeNode('button');
  btn2.textContent = 'Remove';
  assert.equal(pressTwice('dev1', btn2, 'Remove laptop?'), false);
  assert.equal(btn2.textContent, 'Remove laptop?');
  assert.equal(btn2.classList.contains('armed'), true);

  // Timeout restores original label.
  for (const fn of [...timers.values()]) fn();
  assert.equal(btn2.textContent, 'Remove');
  assert.equal(btn2.classList.contains('armed'), false);
});

test('renderBillingBanner keeps Renew now disabled on successful navigation and re-enables on error', async () => {
  const { doc, byId } = makeFakeDoc(['billing-banner']);
  const navigated = [];
  let mode = 'ok';

  renderBillingBanner(
    {
      doc,
      api: async () => {
        if (mode === 'ok') return { url: 'https://billing.example.com/renew/abc' };
        if (mode === 'bad-url') return { url: 'javascript:alert(1)' };
        throw new Error('billing service unavailable');
      },
      navigate: url => navigated.push(url),
      now: () => Date.UTC(2026, 10, 26, 12, 0, 0),
    },
    { is_admin: true },
    { state: 'renew_only', can_renew: true, wake_until: '2026-11-26T12:20:00Z' },
  );

  assert.equal(byId['billing-banner'].hidden, false);
  const renewBtn = findButton(byId['billing-banner'], 'Renew now');
  assert.ok(renewBtn, 'expected Renew now button');

  // Regression check: on successful navigation, button must remain disabled
  // instead of being re-enabled by a finally block while navigation is in flight.
  await renewBtn.onclick();
  assert.deepEqual(navigated, ['https://billing.example.com/renew/abc']);
  assert.equal(renewBtn.disabled, true, 'Renew now must stay disabled during navigation');

  // On API error, button re-enables and error banner displays the message.
  mode = 'err';
  renewBtn.disabled = false;
  await renewBtn.onclick();
  assert.equal(renewBtn.disabled, false);
  const errP = byId['billing-banner'].children[1];
  assert.equal(errP.hidden, false);
  assert.equal(errP.textContent, 'billing service unavailable');

  // Non-https URL is rejected and re-enables button.
  mode = 'bad-url';
  await renewBtn.onclick();
  assert.equal(renewBtn.disabled, false);
  assert.equal(errP.hidden, false);
  assert.match(errP.textContent, /not returned/i);
});

test('renderPenDelete gates submit on pen name match and keeps button disabled on navigation', async () => {
  const { doc, byId } = makeFakeDoc([
    'pen-delete',
    'pen-delete-name',
    'pen-delete-lead-name',
    'pen-delete-label',
    'pen-delete-input',
    'pen-delete-bullets',
    'pen-delete-open-row',
    'pen-delete-confirm-box',
    'pen-delete-go',
    'pen-delete-err',
    'pen-delete-open',
    'pen-delete-cancel',
    'pen-delete-form',
  ]);

  const navigated = [];
  let failOnce = true;
  renderPenDelete(
    {
      doc,
      api: async () => {
        if (failOnce) {
          failOnce = false;
          throw new Error('rate limited');
        }
        return { url: 'https://billing.example.com/delete/xyz' };
      },
      navigate: url => navigated.push(url),
    },
    {
      is_owner: true,
      pen_delete: { can_delete: true, pen: 'bobo', member_count: 3, device_count: 5, other_owners: ['bob'] },
    },
  );

  byId['pen-delete-open'].onclick();
  assert.equal(byId['pen-delete-go'].disabled, true);

  byId['pen-delete-input'].value = 'BOBO';
  byId['pen-delete-input'].oninput();
  assert.equal(byId['pen-delete-go'].disabled, false);

  // First attempt fails -> error shown and button re-enabled because input still matches.
  await byId['pen-delete-form'].onsubmit({ preventDefault() {} });
  assert.equal(byId['pen-delete-err'].hidden, false);
  assert.equal(byId['pen-delete-err'].textContent, 'rate limited');
  assert.equal(byId['pen-delete-go'].disabled, false);

  // Second attempt succeeds -> navigates and keeps button disabled.
  await byId['pen-delete-form'].onsubmit({ preventDefault() {} });
  assert.deepEqual(navigated, ['https://billing.example.com/delete/xyz']);
  assert.equal(byId['pen-delete-go'].disabled, true);
});

test('relativeTime formats seconds, minutes, hours, days, and empty/invalid inputs', () => {
  const now = Date.UTC(2026, 10, 26, 12, 0, 0);
  assert.equal(relativeTime('', now), '');
  assert.equal(relativeTime('not-a-date', now), '');
  assert.equal(relativeTime(new Date(now - 15_000).toISOString(), now), 'just now');
  assert.equal(relativeTime(new Date(now - 5 * 60_000).toISOString(), now), '5m ago');
  assert.equal(relativeTime(new Date(now - 3 * 3600_000).toISOString(), now), '3h ago');
  assert.equal(relativeTime(new Date(now - 4 * 86400_000).toISOString(), now), '4d ago');
});

test('formatUTCDate and formatUTCTime format ISO strings and Dates without string slicing', () => {
  assert.equal(formatUTCDate('2026-11-05T09:07:00Z'), '2026-11-05');
  assert.equal(formatUTCTime('2026-11-05T09:07:00Z'), '09:07');
  assert.equal(formatUTCDate(new Date(Date.UTC(2026, 0, 2, 3, 4))), '2026-01-02');
  assert.equal(formatUTCTime(new Date(Date.UTC(2026, 0, 2, 3, 4))), '03:04');
  assert.equal(formatUTCDate('not-a-date'), '');
  assert.equal(formatUTCTime(''), '');
});
