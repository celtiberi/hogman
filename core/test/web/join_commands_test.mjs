import assert from 'node:assert/strict';
import test from 'node:test';

import { buildJoinCommands, buildManualCommand, buildStartCommand, parseJoinHash } from '../../join-page/commands.js';

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
