(() => {
  const $ = id => document.getElementById(id);
  const api = async (method, path, body) => {
    const r = await fetch('/api' + path, {
      method, cache: 'no-store',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(data.error || ('HTTP ' + r.status)), { status: r.status });
    return data;
  };

  // A link from the keeper fills the code in: https://.../#code=PIG-XXXX-XXXX
  const m = location.hash.match(/code=([A-Za-z0-9-]+)/);
  if (m) $('code').value = m[1].toUpperCase();

  const setNames = () => {
    const p = $('pen').value.trim().toLowerCase() || 'smith';
    document.querySelectorAll('.penname').forEach(e => { e.textContent = p; });
  };

  // Is the pen name free? Asked as you type, gently.
  let checkTimer = null, checkSeq = 0;
  $('pen').addEventListener('input', () => {
    setNames();
    clearTimeout(checkTimer);
    const pen = $('pen').value.trim().toLowerCase();
    const hint = $('pen-hint');
    if (!pen) { hint.className = 'hint'; hint.textContent = ''; hint.append(...defaultHint()); return; }
    checkTimer = setTimeout(async () => {
      const seq = ++checkSeq;
      try {
        const r = await api('GET', '/check?pen=' + encodeURIComponent(pen));
        if (seq !== checkSeq) return;
        hint.className = r.free ? 'hint ok' : 'hint bad';
        hint.textContent = r.free ? `✓ ${pen}.hogman is free` : `✗ ${r.reason}`;
      } catch (e) { if (seq === checkSeq) { hint.className = 'hint bad'; hint.textContent = e.message; } }
    }, 350);
  });
  const defaultHint = () => {
    const s = document.createElement('span'); s.className = 'penname'; s.textContent = 'smith';
    return [document.createTextNode('Your network\'s name. Everything in it ends in .'), s, document.createTextNode('.hogman')];
  };
  $('handle').addEventListener('input', setNames);

  const show = id => { for (const s of ['form', 'working', 'done']) $(s).hidden = s !== id; };

  $('form').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('err').hidden = true;
    const body = { code: $('code').value, pen: $('pen').value, handle: $('handle').value };
    if (!body.code.trim() || !body.pen.trim() || !body.handle.trim()) {
      $('err').textContent = 'Fill in all three.'; $('err').hidden = false; return;
    }
    $('go').disabled = true;
    show('working');
    // A pen can't be raised twice from one page, and leaving mid-way loses the link.
    window.onbeforeunload = () => true;
    try {
      const r = await api('POST', '/create', body);
      $('done-zone').textContent = r.zone;
      $('link').textContent = r.join_link;
      if (r.join_qr_svg) $('qr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(r.join_qr_svg);
      else $('qr').closest('.qr').hidden = true;
      $('copy').onclick = async () => { await navigator.clipboard.writeText(r.join_link); $('copy').textContent = 'Copied'; };
      history.replaceState(null, '', location.pathname);   // the code is used up
      show('done');
    } catch (e) {
      window.onbeforeunload = null;
      show('form');
      $('err').textContent = e.message; $('err').hidden = false;
      $('go').disabled = false;
    }
  });

  api('GET', '/status').then(s => {
    if (!s.open) { $('closed').hidden = false; $('go').disabled = true; }
  }).catch(() => { $('down').hidden = false; });
  setNames();
})();
