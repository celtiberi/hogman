(() => {
  // The secret is kept for this tab only (so a refresh still works) and taken
  // out of the address bar and browser history.
  const KEY = 'hogman-join-link';
  let hash = location.hash.slice(1);
  if (hash) sessionStorage.setItem(KEY, hash); else hash = sessionStorage.getItem(KEY) || '';
  const q = new URLSearchParams(hash);
  const err = m => { const e = document.getElementById('err'); e.textContent = m; e.hidden = false;
                     document.getElementById('what').textContent = ''; };
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
    document.getElementById('what').textContent = '';
    return err('Phones can\'t join yet: the Hogman phone app is coming soon. ' +
               'For now, open this link on a macOS or Linux computer.');
  }
  const cleanLink = `https://${host}/join#${t ? 't=' + t : 'k=' + k}${forShare ? '&for=share' : ''}`;
  const quoted = `'${cleanLink}'`;
  const verb = forShare ? 'share blog 8080 ' : '';
  const longCmd = `curl -fsSLo hogman-join "https://${host}/join/dl/hogman-join-$(uname -s)-$(uname -m)" && chmod +x hogman-join && ./hogman-join ${verb}${quoted}`;
  // Joining: one short command that's the same for everyone; it asks for the
  // link, so the secret never sits in the command. Sharing keeps the long form.
  const unixCmd = forShare ? longCmd : `curl -fsSL https://${host}/start | sh`;
  document.getElementById('cmd').textContent = unixCmd;
  document.getElementById('cmd-manual').textContent = longCmd;
  document.getElementById('link-step').hidden = forShare;
  document.getElementById('manual').hidden = forShare;
  document.getElementById('key-warn').hidden = !forShare;
  document.getElementById('copy-link').onclick = async () => {
    await navigator.clipboard.writeText(cleanLink);
    document.getElementById('copied-link').textContent = 'Copied. Paste it into Terminal when it asks.';
  };
  // Sharing doesn't touch the browser proxy, so no password note there.
  document.getElementById('pw-note').hidden = forShare;
  if (forShare) {
    document.getElementById('lead').textContent =
      'Copy this into a terminal on the computer hosting your app or folder. It downloads hogman-join (no other software needed):';
  }
  const show = os => {
    const isWin = os === 'win';
    document.getElementById('unix-panel').hidden = isWin;
    document.getElementById('win-panel').hidden = !isWin;
    document.getElementById('lead').hidden = isWin;
    document.getElementById('join-details').hidden = isWin || forShare;
    document.getElementById('share-details').hidden = isWin || !forShare;
    document.getElementById('sums-line').hidden = isWin;
    document.querySelectorAll('.tabs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.os === os)));
  };
  document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => show(b.dataset.os));
  show(/Windows/.test(navigator.userAgent) ? 'win' : 'unix');
  document.getElementById('copy').onclick = async () => {
    await navigator.clipboard.writeText(unixCmd);
    document.getElementById('copied').textContent = 'Copied.';
  };
  document.getElementById('redeem').textContent = kind === 'invite' ? 'asks you to pick your name, validates' : 'connects to';
  fetch('/hogman/v1/network').then(r => r.json()).then(n => {
    document.querySelectorAll('.zone').forEach(el => { el.textContent = '.' + n.zone; });
    document.getElementById('title').textContent = (forShare ? 'Share into ' : 'Join ') + n.zone;
    document.getElementById('what').textContent = kind === 'invite'
      ? 'You have been invited. This link works once.'
      : kind === 'share'
        ? 'Put something in the pen from this computer: change blog to the name you want, and 8080 to your app\'s port (or a folder). This link works once, for an hour.'
        : 'Add another device. This link works once, for an hour.';
    if (n.cert_mode && n.cert_mode !== 'public') {
      return err('This network returned an unrecognized certificate mode.');
    }
    document.getElementById('main').hidden = false;
  }).catch(() => err('Could not reach the network. Try again shortly.'));
})();
