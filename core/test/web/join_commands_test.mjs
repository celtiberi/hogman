import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  buildJoinCommands,
  buildManualCommand,
  buildStartCommand,
  buildWindowsManualCommand,
  buildWindowsStartCommand,
  parseJoinHash,
} from '../../join-page/commands.js';
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

  // Windows PowerShell commands enforce HTTPS-only curl.exe, avoid PS 5.1-incompatible '&&',
  // and pass -ExpectedHost and quoted arguments cleanly.
  assert.equal(buildWindowsStartCommand(HOST, link), personalJoin.winStartCmd);
  assert.equal(buildWindowsManualCommand(HOST, link), personalJoin.winManualCmd);
  for (const cmd of [
    personalJoin.winStartCmd,
    personalJoin.winManualCmd,
    personalShare.winStartCmd,
    personalShare.winManualCmd,
    workShare.winStartCmd,
    workShare.winManualCmd,
  ]) {
    assert.ok(cmd.includes("curl.exe -fsSL --proto '=https' --proto-redir '=https'"), `missing strict curl.exe in: ${cmd}`);
    assert.ok(!cmd.includes('&&'), `Windows PowerShell 5.1 does not support '&&': ${cmd}`);
  }
  assert.ok(personalJoin.winStartCmd.includes(`'https://${HOST}/start.ps1'`));
  assert.ok(personalJoin.winStartCmd.includes(`-ExpectedHost '${HOST}' '${link}'`));
  assert.ok(personalShare.winStartCmd.endsWith(`-ExpectedHost '${HOST}' '${shareLink}' 'share' 'blog' '8080' }`));
  assert.ok(workShare.winStartCmd.endsWith(`-ExpectedHost '${HOST}' '${shareLink}' 'share' 'cooler-1' 'http://192.168.1.40' }`));
  assert.ok(personalJoin.winManualCmd.includes('hogman-windows-$a.exe'));
  assert.ok(personalShare.winManualCmd.includes(`.\\hogman.exe share blog 8080 '${shareLink}'`));
  assert.ok(workShare.winManualCmd.includes(`.\\hogman.exe share cooler-1 http://192.168.1.40 '${shareLink}'`));
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
    'err', 'what', 'cmd', 'cmd-manual', 'manual', 'proxy-note', 'proxy-zone', 'vpn-note', 'vpn-zone',
    'win-cmd', 'win-cmd-manual', 'win-manual', 'win-proxy-note', 'win-proxy-zone', 'win-vpn-note', 'win-vpn-zone',
    'win-expect-head', 'win-copy', 'win-copied',
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
  assert.equal(elems.get('proxy-zone').textContent, 'demo.pens.hogman.network');
  assert.equal(elems.get('vpn-zone').textContent, 'demo.pens.hogman.network');
  assert.equal(elems.get('win-proxy-zone').textContent, 'demo.pens.hogman.network');
  assert.equal(elems.get('win-vpn-zone').textContent, 'demo.pens.hogman.network');
  assert.ok(elems.get('win-cmd').textContent.includes(`https://${HOST}/start.ps1`));
  assert.ok(elems.get('win-cmd').textContent.includes(`https://${HOST}/join#t=abc123`));
});

test('initJoinPage selects Windows panel on Windows UA and copies PowerShell command', async () => {
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
    'err', 'what', 'cmd', 'cmd-manual', 'manual', 'proxy-note', 'proxy-zone', 'vpn-note', 'vpn-zone',
    'win-cmd', 'win-cmd-manual', 'win-manual', 'win-proxy-note', 'win-proxy-zone', 'win-vpn-note', 'win-vpn-zone',
    'win-expect-head', 'win-copy', 'win-copied',
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

  let copiedText = '';
  await initJoinPage({
    doc,
    loc: { hash: '#t=win123', host: HOST, pathname: '/join' },
    nav: {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      clipboard: { writeText: async text => { copiedText = text; } },
    },
    storage: null,
    hist: { replaceState() {} },
    fetchFn: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ zone: 'demo.pens.hogman.network', theme: '' }),
    }),
  });

  assert.equal(elems.get('unix-panel').hidden, true);
  assert.equal(elems.get('win-panel').hidden, false);
  assert.equal(elems.get('lead').hidden, false);
  assert.ok(elems.get('lead').textContent.includes('PowerShell'));
  assert.equal(elems.get('join-details').hidden, false);
  assert.equal(elems.get('sums-line').hidden, false);
  await elems.get('win-copy').onclick();
  assert.equal(copiedText, elems.get('win-cmd').textContent);
  assert.equal(elems.get('win-copied').textContent, 'Copied.');
});

test('join-page extension install button and copy use same-origin icon and official store URL', () => {
  const html = fs.readFileSync(new URL('../../join-page/index.html', import.meta.url), 'utf8');
  const storeURL = 'https://chromewebstore.google.com/detail/hogman/mgokdogedagoejnjmjpmbcmicbmhplkk';
  assert.ok(!html.includes('nothing else to set'), 'join-page must not claim nothing else to set');
  assert.ok(!html.includes('Windows support is coming soon'), 'join-page Windows tab must be active');
  assert.ok(html.includes('href="/start.ps1"'), 'join-page Windows tab must link to /start.ps1');
  assert.ok(
    html.includes(`<a class="ext-btn" href="${storeURL}" target="_blank" rel="noopener noreferrer">`),
    'join-page must render a real anchor button pointing to the official Chrome Web Store URL',
  );
  assert.ok(
    html.includes('<img class="ext-btn-icon" src="/join/assets/hogman-icon.webp" width="32" height="32" alt="">'),
    'join-page extension button must use the same-origin D-46 icon with empty alt',
  );
  assert.ok(html.includes('Install Hogman Extension'));
  assert.ok(html.includes('open its popup and turn on <code id="proxy-zone">this pen</code>. No proxy settings needed'));
  assert.ok(html.includes('open its popup and turn on <code id="vpn-zone">this pen</code>'));
  assert.ok(html.includes('open its popup and turn on <code id="win-proxy-zone">this pen</code>. No proxy settings needed'));
  assert.ok(html.includes('open its popup and turn on <code id="win-vpn-zone">this pen</code>'));
});
