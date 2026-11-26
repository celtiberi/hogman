import assert from 'node:assert/strict';
import test from 'node:test';

import { buildJoinCommands, buildManualCommand, buildStartCommand, parseJoinHash } from '../../join-page/commands.js';
import { initJoinPage } from '../../join-page/join.js';

const HOST = 'example.gate.hogman.network';

test('parseJoinHash accepts invite, device, and share links and rejects malformed/legacy hashes', () => {
  assert.deepEqual(parseJoinHash('#t=abc_123.XYZ-9', HOST), {
    ok: true,
    kind: 'invite',
    forShare: false,
    cleanLink: `https://${HOST}/join#t=abc_123.XYZ-9`,
  });

  assert.deepEqual(parseJoinHash('k=hskey-123', HOST), {
    ok: true,
    kind: 'device',
    forShare: false,
    cleanLink: `https://${HOST}/join#k=hskey-123`,
  });

  assert.deepEqual(parseJoinHash('k=hskey-123&for=share', HOST), {
    ok: true,
    kind: 'share',
    forShare: true,
    cleanLink: `https://${HOST}/join#k=hskey-123&for=share`,
  });

  // Invite token ignores for=share (only device keys can be share links).
  assert.deepEqual(parseJoinHash('t=inv1&for=share', HOST), {
    ok: true,
    kind: 'invite',
    forShare: false,
    cleanLink: `https://${HOST}/join#t=inv1`,
  });

  for (const [label, hash, host] of [
    ['legacy fp', 't=abc&fp=deadbeef', HOST],
    ['empty hash', '', HOST],
    ['empty token', 't=&for=share', HOST],
    ['both t and k', 't=abc&k=def', HOST],
    ['shell metachar in token', 't=abc;id', HOST],
    ['shell metachar in host', 't=abc', 'evil.com;id'],
  ]) {
    const res = parseJoinHash(hash, host);
    assert.equal(res.ok, false, `expected failure for ${label}`);
    assert.ok(res.error.length > 0, `expected error message for ${label}`);
  }
});

test('buildJoinCommands generates zsh-safe quoted start and manual commands for personal and work pens', () => {
  const link = `https://${HOST}/join#k=hskey-TEST`;
  const personalJoin = buildJoinCommands({ host: HOST, cleanLink: link, forShare: false, isWork: false });
  assert.equal(
    personalJoin.startCmd,
    `curl -fsSL --proto '=https' --proto-redir '=https' https://${HOST}/start | HOGMAN_EXPECTED_HOST='${HOST}' sh -s -- '${link}'`,
  );
  assert.equal(
    personalJoin.manualCmd,
    `curl -fsSL --proto '=https' --proto-redir '=https' -o hogman "https://${HOST}/join/dl/hogman-$(uname -s)-$(uname -m)" && chmod +x hogman && ./hogman '${link}'`,
  );

  const shareLink = `https://${HOST}/join#k=hskey-TEST&for=share`;
  const personalShare = buildJoinCommands({ host: HOST, cleanLink: shareLink, forShare: true, isWork: false });
  assert.ok(personalShare.startCmd.endsWith(`'${shareLink}' share blog 8080`));
  assert.ok(personalShare.manualCmd.endsWith(`share blog 8080 '${shareLink}'`));

  const workShare = buildJoinCommands({ host: HOST, cleanLink: shareLink, forShare: true, isWork: true });
  assert.ok(workShare.startCmd.endsWith(`'${shareLink}' share cooler-1 http://192.168.1.40`));
  assert.ok(workShare.manualCmd.endsWith(`share cooler-1 http://192.168.1.40 '${shareLink}'`));

  // Direct helpers match buildJoinCommands output.
  assert.equal(buildStartCommand(HOST, link), personalJoin.startCmd);
  assert.equal(buildManualCommand(HOST, link), personalJoin.manualCmd);
});

test('initJoinPage tolerates a throwing sessionStorage getter when storage is omitted', async () => {
  const elems = new Map();
  const makeEl = id => {
    const el = {
      id,
      textContent: '',
      hidden: id === 'err' || id === 'main',
      dataset: {},
      onclick: null,
      setAttribute() {},
      replaceChildren() {},
    };
    elems.set(id, el);
    return el;
  };
  for (const id of [
    'err', 'what', 'cmd', 'cmd-manual', 'manual', 'proxy-note', 'vpn-note',
    'expect-head', 'lead', 'unix-panel', 'win-panel', 'join-details',
    'share-details', 'sums-line', 'copy', 'copied', 'redeem', 'title', 'main',
  ]) {
    makeEl(id);
  }
  const doc = {
    documentElement: { dataset: {} },
    title: '',
    getElementById: id => elems.get(id) || null,
    querySelector: () => null,
    querySelectorAll: () => [],
    createElement: tag => ({ tag }),
    createTextNode: text => ({ text }),
  };

  const prevDesc = Object.getOwnPropertyDescriptor(globalThis, 'sessionStorage');
  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true,
    get() {
      throw new Error('SecurityError: storage blocked');
    },
  });
  let replacedPath = null;
  try {
    await initJoinPage({
      doc,
      loc: { hash: '#t=abc123', host: HOST, pathname: '/join' },
      nav: { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X)', clipboard: { writeText: async () => {} } },
      hist: { replaceState: (_s, _t, path) => { replacedPath = path; } },
      fetchFn: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ zone: 'demo.pens.hogman.network', theme: '' }),
      }),
    });
  } finally {
    if (prevDesc) Object.defineProperty(globalThis, 'sessionStorage', prevDesc);
    else delete globalThis.sessionStorage;
  }

  assert.equal(replacedPath, '/join');
  assert.equal(elems.get('err').hidden, true);
  assert.equal(elems.get('err').textContent, '');
  assert.equal(elems.get('main').hidden, false);
  assert.ok(elems.get('cmd').textContent.includes(`https://${HOST}/join#t=abc123`));
  assert.equal(elems.get('title').textContent, 'Join demo.pens.hogman.network');
});
