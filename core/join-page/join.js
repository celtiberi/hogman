(() => {
  const $ = id => document.getElementById(id);

  const setFavicon = href => {
    document.querySelectorAll('link[rel="icon"]').forEach(el => el.remove());
    const link = document.createElement('link');
    link.rel = 'icon';
    link.type = 'image/svg+xml';
    link.href = href;
    document.head.appendChild(link);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', '#14181f');
  };

  const replaceLinks = (container, items, sep) => {
    if (!container) return;
    container.replaceChildren();
    items.forEach(([label, href], idx) => {
      if (sep && idx > 0) container.append(document.createTextNode(sep));
      const a = document.createElement('a');
      a.href = href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = label;
      container.append(a);
    });
  };

  const applyWorkTheme = (zone, forShare) => {
    document.documentElement.dataset.theme = 'work';
    document.title = (forShare ? 'Bridge · ' : 'Join · ') + 'Hogman for Work';
    setFavicon('/join/assets/work-favicon.svg');

    $('brand-link').href = 'https://work.hogman.network/';
    $('brand-link').setAttribute('aria-label', 'Hogman for Work');
    $('brand-icon').src = '/join/assets/work-favicon.svg';
    $('brand-name').textContent = 'Hogman';
    $('brand-tag').hidden = false;
    $('gate-pill').textContent = 'Network gate';

    replaceLinks($('nav-links'), [
      ['Onboarding guide', 'https://work.hogman.network/docs/join.html'],
      ['Bridging guide', 'https://work.hogman.network/docs/share.html'],
      ['FAQ', 'https://work.hogman.network/docs/faq.html'],
      ['work.hogman.network', 'https://work.hogman.network/'],
    ]);

    $('vpn-note').replaceChildren(
      Object.assign(document.createElement('strong'), { textContent: 'Using a corporate VPN (or WireGuard, ProtonVPN, Mullvad)? ' }),
      document.createTextNode('macOS VPN apps override the system automatic proxy while connected. Pause the VPN while visiting pen dashboards, or set Firefox\u2019s built-in '),
      Object.assign(document.createElement('em'), { textContent: 'Automatic proxy configuration URL' }),
      document.createTextNode(' to the address printed by '),
      Object.assign(document.createElement('code'), { textContent: 'hogman' }),
      document.createTextNode('.')
    );

    $('foot-tagline').textContent = 'Hogman for Work \u00b7 Private HTTPS access';
    replaceLinks($('foot-links'), [
      ['work.hogman.network', 'https://work.hogman.network/'],
      ['Onboarding guide', 'https://work.hogman.network/docs/join.html'],
      ['Security', 'https://work.hogman.network/docs/security.html'],
      ['FAQ', 'https://work.hogman.network/docs/faq.html'],
    ], ' \u00b7 ');
    if (forShare) {
      $('lead').textContent = 'Run this command on the on-site computer or bridge machine. It downloads hogman and bridges your LAN controller or internal web app over HTTPS:';
      $('title').textContent = 'Bridge into ' + zone;
    }
  };

  // The secret is kept for this tab only (so a refresh still works) and taken
  // out of the address bar and browser history.
  const KEY = 'hogman-link';
  let hash = location.hash.slice(1);
  if (hash) sessionStorage.setItem(KEY, hash); else hash = sessionStorage.getItem(KEY) || '';
  const q = new URLSearchParams(hash);
  const err = m => { const e = $('err'); e.textContent = m; e.hidden = false;
                     $('what').textContent = ''; };
  history.replaceState(null, '', location.pathname);
  const t = q.get('t');
  const k = q.get('k');
  const fp = q.get('fp');
  if (fp) {
    return err('This link is from an older release and is no longer valid. Ask whoever sent it for a fresh one.');
  }
  if (!(t || k)) {
    return err('This link is incomplete. Ask whoever sent it for a fresh one, and copy it whole.');
  }
  if (t && k) {
    return err('This link is invalid. Ask whoever sent it for a fresh one.');
  }
  const host = location.host;
  if ((t && !/^[a-zA-Z0-9._-]+$/.test(t)) ||
      (k && !/^[a-zA-Z0-9._-]+$/.test(k)) ||
      !/^[a-zA-Z0-9._:-]+$/.test(host)) {
    return err('This link contains unexpected characters. Ask whoever sent it for a fresh one.');
  }
  // A server link (for=share) only puts something in the pen with `share`;
  // it never joins a whole computer.
  const forShare = !t && q.get('for') === 'share';
  const kind = t ? 'invite' : (forShare ? 'share' : 'device');
  // Phones can't run the join command. Say so plainly instead of showing it.
  if (/iPhone|iPad|iPod|Android/i.test(navigator.userAgent)) {
    $('what').textContent = '';
    return err('Phones can\'t join yet: the Hogman phone app is coming soon. ' +
               'For now, open this link on a macOS or Linux computer.');
  }
  const cleanLink = `https://${host}/join#${t ? 't=' + t : 'k=' + k}${forShare ? '&for=share' : ''}`;
  const quoted = `'${cleanLink}'`;
  const makeLongCmd = verb => `curl -fsSLo hogman "https://${host}/join/dl/hogman-$(uname -s)-$(uname -m)" && chmod +x hogman && ./hogman ${verb}${quoted}`;
  const verb = forShare ? 'share blog 8080 ' : '';
  let longCmd = makeLongCmd(verb);
  // Joining: one short command that's the same for everyone; it asks for the
  // link, so the secret never sits in the command. Sharing keeps the long form.
  let unixCmd = forShare ? longCmd : `curl -fsSL https://${host}/start | sh`;
  $('cmd').textContent = unixCmd;
  $('cmd-manual').textContent = longCmd;
  $('link-step').hidden = forShare;
  $('manual').hidden = forShare;
  $('key-warn').hidden = !forShare;
  $('copy-link').onclick = async () => {
    await navigator.clipboard.writeText(cleanLink);
    $('copied-link').textContent = 'Copied. Paste it into Terminal when it asks.';
  };
  // Sharing doesn't touch the browser proxy, so no password or VPN proxy note there.
  $('pw-note').hidden = forShare;
  $('vpn-note').hidden = forShare;
  if (forShare) {
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
    document.querySelectorAll('.tabs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.os === os)));
  };
  document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => show(b.dataset.os));
  show(/Windows/.test(navigator.userAgent) ? 'win' : 'unix');
  $('copy').onclick = async () => {
    await navigator.clipboard.writeText(unixCmd);
    $('copied').textContent = 'Copied.';
  };
  $('redeem').textContent = kind === 'invite' ? 'asks you to pick your name, validates' : 'verifies';
  fetch('/hogman/v1/network').then(r => r.json()).then(n => {
    const isWork = n.theme === 'work';
    document.querySelectorAll('.zone').forEach(el => { el.textContent = '.' + n.zone; });
    $('title').textContent = (forShare ? 'Share into ' : 'Join ') + n.zone;
    if (isWork) {
      applyWorkTheme(n.zone, forShare);
      if (forShare) {
        longCmd = makeLongCmd('share cooler-1 http://192.168.1.40 ') + ' --background';
        unixCmd = longCmd;
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
      return err('This network returned an unrecognized certificate mode.');
    }
    $('main').hidden = false;
  }).catch(() => err('Could not reach the network. Try again shortly.'));
})();
