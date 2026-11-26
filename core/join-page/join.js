import { buildJoinCommands, parseJoinHash } from './commands.js';

function replaceLinks(doc, container, items, sep) {
  if (!container) return;
  container.replaceChildren();
  items.forEach(([label, href], idx) => {
    if (sep && idx > 0) container.append(doc.createTextNode(sep));
    const a = doc.createElement('a');
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = label;
    container.append(a);
  });
}

function applyWorkTheme(doc, zone, forShare) {
  const $ = id => doc.getElementById(id);
  doc.documentElement.dataset.theme = 'work';
  doc.title = (forShare ? 'Bridge · ' : 'Join · ') + 'Hogman for Work';
  const meta = doc.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', '#14181f');

  $('brand-link').href = 'https://work.hogman.network/';
  $('brand-link').setAttribute('aria-label', 'Hogman for Work');
  $('brand-name').textContent = 'Hogman';
  $('brand-tag').hidden = false;
  $('gate-pill').textContent = 'Network gate';

  replaceLinks(doc, $('nav-links'), [
    ['Onboarding guide', 'https://work.hogman.network/docs/join.html'],
    ['Bridging guide', 'https://work.hogman.network/docs/share.html'],
    ['FAQ', 'https://work.hogman.network/docs/faq.html'],
    ['work.hogman.network', 'https://work.hogman.network/'],
  ]);

  $('vpn-note').replaceChildren(
    Object.assign(doc.createElement('strong'), { textContent: 'Using a corporate VPN (or WireGuard, ProtonVPN, Mullvad)? ' }),
    doc.createTextNode('macOS VPN apps override the system automatic proxy while connected. Use the Hogman browser extension, set Firefox\u2019s built-in '),
    Object.assign(doc.createElement('em'), { textContent: 'Automatic proxy configuration URL' }),
    doc.createTextNode(' to the address printed by '),
    Object.assign(doc.createElement('code'), { textContent: 'hogman' }),
    doc.createTextNode(', or pause the VPN while visiting pen dashboards in Safari.')
  );

  $('foot-tagline').textContent = 'Hogman for Work \u00b7 Private HTTPS access';
  replaceLinks(doc, $('foot-links'), [
    ['work.hogman.network', 'https://work.hogman.network/'],
    ['Onboarding guide', 'https://work.hogman.network/docs/join.html'],
    ['Security', 'https://work.hogman.network/docs/security.html'],
    ['FAQ', 'https://work.hogman.network/docs/faq.html'],
  ], ' \u00b7 ');
  if (forShare) {
    $('lead').textContent = 'Run this command on the on-site computer or bridge machine. It downloads hogman and bridges your LAN controller or internal web app over HTTPS:';
    $('title').textContent = 'Bridge into ' + zone;
  }
}

export function initJoinPage({
  doc = document,
  loc = location,
  nav = navigator,
  storage,
  hist = history,
  fetchFn = fetch,
} = {}) {
  const $ = id => doc.getElementById(id);
  const err = m => {
    const e = $('err');
    e.textContent = m;
    e.hidden = false;
    $('what').textContent = '';
  };

  // The secret is kept for this tab only (so a refresh still works) and taken
  // out of the address bar and browser history.
  const KEY = 'hogman-link';
  let hash = loc.hash.slice(1);
  try {
    const store = storage === undefined ? sessionStorage : storage;
    if (store) {
      if (hash) store.setItem(KEY, hash);
      else hash = store.getItem(KEY) || '';
    }
  } catch (_) {
    // sessionStorage can throw in restricted privacy contexts; continue with URL hash.
  }
  hist.replaceState(null, '', loc.pathname);

  const parsed = parseJoinHash(hash, loc.host);
  if (!parsed.ok) {
    err(parsed.error);
    return Promise.resolve();
  }

  // Phones can't run the join command. Say so plainly instead of showing it.
  if (/iPhone|iPad|iPod|Android/i.test(nav.userAgent)) {
    err('Phones can\'t join yet: the Hogman phone app is coming soon. ' +
        'For now, open this link on a macOS or Linux computer.');
    return Promise.resolve();
  }

  const { kind, forShare, cleanLink } = parsed;
  const host = loc.host;
  let { startCmd: unixCmd, manualCmd: longCmd } = buildJoinCommands({ host, cleanLink, forShare, isWork: false });
  $('cmd').textContent = unixCmd;
  $('cmd-manual').textContent = longCmd;
  $('manual').hidden = forShare;
  // Sharing doesn't need browser proxy setup or VPN coexistence steps.
  $('proxy-note').hidden = forShare;
  $('vpn-note').hidden = forShare;
  if (forShare) {
    $('expect-head').textContent = 'What to expect on macOS';
    $('lead').textContent =
      'Copy this into a terminal on the computer hosting your app or folder. It downloads hogman (no other software needed):';
  }

  const show = os => {
    const isWin = os === 'win';
    $('unix-panel').hidden = isWin;
    $('win-panel').hidden = !isWin;
    $('lead').hidden = isWin;
    $('join-details').hidden = isWin || forShare;
    $('share-details').hidden = isWin || !forShare;
    $('sums-line').hidden = isWin;
    doc.querySelectorAll('.tabs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.os === os)));
  };
  doc.querySelectorAll('.tabs button').forEach(b => { b.onclick = () => show(b.dataset.os); });
  show(/Windows/.test(nav.userAgent) ? 'win' : 'unix');

  $('copy').onclick = async () => {
    try {
      await nav.clipboard.writeText(unixCmd);
      $('copied').textContent = 'Copied.';
    } catch (_) {
      $('copied').textContent = 'Copy failed — select the command above.';
    }
  };
  $('redeem').textContent = kind === 'invite' ? 'asks you to pick your name, validates' : 'verifies';

  return fetchFn('/hogman/v1/network').then(r => {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(n => {
    if (!n || !n.zone) throw new Error('missing zone');
    const isWork = n.theme === 'work';
    doc.querySelectorAll('.zone').forEach(el => { el.textContent = '.' + n.zone; });
    $('title').textContent = (forShare ? 'Share into ' : 'Join ') + n.zone;
    if (isWork) {
      applyWorkTheme(doc, n.zone, forShare);
      if (forShare) {
        ({ startCmd: unixCmd, manualCmd: longCmd } = buildJoinCommands({ host, cleanLink, forShare, isWork: true }));
        $('cmd').textContent = unixCmd;
        $('cmd-manual').textContent = longCmd;
      }
    }
    $('what').textContent = kind === 'invite'
      ? (isWork ? 'You have been invited to join this private network. This link works once.' : 'You have been invited. This link works once.')
      : kind === 'share'
        ? (isWork
            ? 'Bridge a local LAN controller or internal web app into this pen: replace cooler-1 with a short name and http://192.168.1.40 with your local LAN URL, port, or folder. This link works once, for an hour.'
            : 'Put something in the pen from this computer: change blog to the name you want, and 8080 to your app\'s port (or a folder). This link works once, for an hour.')
        : 'Add another device. This link works once, for an hour.';
    if (n.cert_mode && n.cert_mode !== 'public') {
      err('This network returned an unrecognized certificate mode.');
      return;
    }
    $('main').hidden = false;
  }).catch(() => err('Could not reach the network. Try again shortly.'));
}

if (typeof document !== 'undefined') {
  initJoinPage();
}
