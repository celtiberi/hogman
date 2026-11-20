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
    const p = $('pen').value.trim().toLowerCase() || '<network>';
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
    const s = document.createElement('span'); s.className = 'penname'; s.textContent = '<network>';
    return [document.createTextNode('For your private network itself. Sites and addresses will end in .'), s, document.createTextNode('.hogman')];
  };
  $('handle').addEventListener('input', setNames);
  for (const f of ['pen', 'handle']) $(f).addEventListener('change', setNames);   // autofill, paste, scripts

  const show = id => { for (const s of ['form', 'wait', 'waited', 'working', 'done']) $(s).hidden = s !== id; };

  // The waiting list: for when the farm is full, or there's no code.
  $('to-wait').addEventListener('click', ev => { ev.preventDefault(); show('wait'); $('w-email').focus(); });
  $('to-form').addEventListener('click', ev => { ev.preventDefault(); show('form'); });
  $('waited-back').addEventListener('click', ev => { ev.preventDefault(); history.replaceState(null, '', location.pathname); show('wait'); });
  $('waited-code').addEventListener('click', ev => { ev.preventDefault(); history.replaceState(null, '', location.pathname); show('form'); });
  $('w-leave').addEventListener('click', async () => {
    $('w-err').hidden = true;
    const email = $('w-email').value.trim();
    if (!email.includes('@')) { $('w-err').textContent = 'Type the email you joined with, then press this again.'; $('w-err').hidden = false; return; }
    try {
      await api('POST', '/waitlist/leave', { email });
      $('waited-title').textContent = "You're off the list";
      $('waited-text').textContent = `If ${email} was on the waiting list, it isn't any more, and we've deleted it.`;
      show('waited');
    } catch (e) { $('w-err').textContent = e.message; $('w-err').hidden = false; }
  });
  $('wait').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('w-err').hidden = true;
    const email = $('w-email').value.trim();
    if (!email.includes('@')) { $('w-err').textContent = 'Your email, please.'; $('w-err').hidden = false; return; }
    $('w-go').disabled = true;
    try {
      const r = await api('POST', '/waitlist', { email, pen: $('w-pen').value.trim(), note: $('w-note').value.trim() });
      $('waited-title').textContent = r.already ? "You're already on the list" : "You're on the list";
      $('waited-text').textContent = `You're number ${r.place}. We'll email ${email} a sign-up code when there's room.`;
      show('waited');
    } catch (e) { $('w-err').textContent = e.message; $('w-err').hidden = false; }
    finally { $('w-go').disabled = false; }
  });

  // Raising a pen is a job on the server: start it, then check on it. The job's
  // id is kept for this tab, so a reload carries on instead of losing the link.
  const JOB = 'hogman-signup-job';
  const stages = [[0, 'Building the fence'], [8, 'Minting your certificate authority'],
                  [20, 'Opening the gate'], [35, 'Raking the last of the straw'], [90, 'Taking longer than usual; hang on']];
  const showDone = r => {
    $('done-zone').textContent = r.zone;
    const homeURL = 'https://home.' + r.zone;
    $('done-home').textContent = homeURL;
    $('done-home-step').textContent = homeURL;
    $('link').textContent = r.join_link;
    if (r.join_qr_svg) $('qr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(r.join_qr_svg);
    else $('qr').closest('.qr').hidden = true;
    $('copy').onclick = async () => { await navigator.clipboard.writeText(r.join_link); $('copy').textContent = 'Copied'; };
    sessionStorage.removeItem(JOB);
    history.replaceState(null, '', location.pathname);   // the code is used up
    show('done');
  };
  const fail = msg => {
    sessionStorage.removeItem(JOB);
    show('form');
    $('err').textContent = msg; $('err').hidden = false;
    $('go').disabled = false;
  };
  const follow = async id => {
    show('working');
    const t0 = Date.now();
    for (;;) {
      let j = null;
      try { j = await api('GET', '/job?id=' + encodeURIComponent(id)); }
      catch (e) { if (e.status === 404) return fail(e.message); }   // otherwise a blip: keep checking
      if (j && j.state === 'done') return showDone(j.result);
      if (j && j.state === 'failed') return fail(j.error);
      const secs = j ? j.seconds : Math.round((Date.now() - t0) / 1000);
      const stage = stages.filter(([at]) => secs >= at).pop()[1];
      $('stage').textContent = `${stage}… ${secs}s`;
      $('bar').style.width = Math.min(95, 5 + secs * 1.5) + '%';   // only ever moves forward
      await new Promise(r => setTimeout(r, 2000));
    }
  };

  $('form').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('err').hidden = true;
    setNames();
    const body = { code: $('code').value, pen: $('pen').value, handle: $('handle').value };
    if (!body.code.trim() || !body.pen.trim() || !body.handle.trim()) {
      $('err').textContent = 'Fill in all three.'; $('err').hidden = false; return;
    }
    $('go').disabled = true;
    try {
      const r = await api('POST', '/create', body);
      sessionStorage.setItem(JOB, r.job);
      await follow(r.job);
    } catch (e) { fail(e.message); }
  });
  const pending = sessionStorage.getItem(JOB);
  if (pending) follow(pending);

  if (location.hash === '#wait') show('wait');   // a link straight to the waiting list
  api('GET', '/status').then(s => {
    if (!s.open) { $('closed').hidden = false; $('go').disabled = true; show('wait'); }
  }).catch(() => { $('down').hidden = false; });
  setNames();
})();
