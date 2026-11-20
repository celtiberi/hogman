(() => {
  const $ = id => document.getElementById(id);
  const api = async (method, path, body) => {
    const r = await fetch('/api' + path, {
      method, headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined, cache: 'no-store',
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
    return data;
  };

  let me = null;
  let timer = null;
  const armed = new Set();

  const render = () => {
    $('hello').textContent = `You're in, ${me.member.handle}.`;
    $('whoami').textContent = `On ${me.zone} from ${me.this_device.name}. This page is only reachable from inside the network.`;
    document.querySelectorAll('.zone').forEach(e => { e.textContent = me.zone; });
    if (!me.devices) return;   // servers get a short answer and no device controls
    $('mine').hidden = false;
    const ul = $('devices');
    ul.replaceChildren();
    for (const d of me.devices) {
      const li = document.createElement('li');
      const name = document.createElement('span'); name.className = 'grow'; name.textContent = d.name;
      const kind = document.createElement('span'); kind.className = 'tag'; kind.textContent = d.kind;
      li.append(name, kind);
      if (d.id === me.this_device.id) {
        const here = document.createElement('span'); here.className = 'here'; here.textContent = 'this device';
        li.append(here);
      } else {
        const rm = document.createElement('button'); rm.className = 'link danger'; rm.type = 'button'; rm.textContent = 'Remove';
        rm.onclick = async () => {
          if (!confirmRemove(d.id, d.name)) return;
          rm.disabled = true;
          try { await api('DELETE', '/devices/' + d.id); await load(); }
          catch (e) { rm.disabled = false; showError(e); }
        };
        li.append(rm);
      }
      ul.append(li);
    }
  };

  // --------------------------------------------------------- directory --

  const loadDirectory = async () => {
    const sites = await api('GET', '/directory');
    $('sites').hidden = false;
    $('sites-err').hidden = true;
    const ul = $('directory');
    ul.replaceChildren();
    $('sites-empty').hidden = sites.length > 0;
    for (const s of sites) {
      const li = document.createElement('li');
      const main = document.createElement('div');
      main.className = 'site-main';
      const a = document.createElement('a');
      a.className = 'site-link';
      a.href = 'https://' + s.name;
      a.rel = 'noopener';
      a.textContent = s.name;
      main.append(a);
      if (s.note) {
        const note = document.createElement('div');
        note.className = 'muted small';
        note.textContent = s.note;
        main.append(note);
      }
      const by = document.createElement('span');
      by.className = 'muted small';
      by.textContent = `run by ${s.member}`;
      li.append(main, by);
      ul.append(li);
    }
  };

  // A plain inline confirmation instead of a browser dialog.
  const confirmRemove = (id, name) => {
    if (armed.has(id)) { armed.delete(id); return true; }
    armed.add(id);
    showError(new Error(`Press Remove again to take ${name} off the network.`));
    setTimeout(() => { armed.delete(id); }, 5000);
    return false;
  };

  const showError = e => { const p = $('adderr'); p.textContent = e.message; p.hidden = false; };

  const add = async kind => {
    $('adderr').hidden = true;
    $('add-personal').disabled = $('add-server').disabled = true;
    try {
      const r = await api('POST', '/devices', { kind });
      $('qr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(r.join_qr_svg || '');
      // A share link is for a computer: no phone QR, and say what to run.
      $('qr').hidden = !r.join_qr_svg || kind === 'server';
      $('phone-line').hidden = kind === 'server';
      $('computer-line').textContent = kind === 'server'
        ? 'Share link: on the computer that runs the thing you want to share, open this link (it shows the command), or run ./hogman-join share NAME PORT-or-FOLDER \'<this link>\':'
        : 'Computer: open this link on it and follow the steps:';
      $('linktext').textContent = r.join_link;
      $('newlink').hidden = false;
      $('copy').onclick = async () => {
        await navigator.clipboard.writeText(r.join_link);
        $('copy').textContent = 'Copied';
      };
      $('copy').textContent = 'Copy link';
      clearInterval(timer);
      const tick = () => {
        const left = r.expires_at - Date.now() / 1000;
        if (left <= 0) {
          $('expires').textContent = 'Expired. Make a new one.';
          $('qr').classList.add('expired');
          clearInterval(timer);
          return;
        }
        $('expires').textContent = `${kind === 'server' ? 'Share link. ' : ''}Works once, expires in ${Math.ceil(left / 60)} min.`;
      };
      $('qr').classList.remove('expired');
      tick();
      timer = setInterval(tick, 15000);
    } catch (e) { showError(e); }
    finally { $('add-personal').disabled = $('add-server').disabled = false; }
  };
  $('add-personal').onclick = () => add('personal');
  $('add-server').onclick = () => add('server');

  // ------------------------------------------------------------ invites --

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };
  const day = t => new Date(t * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const when = t => new Date(t * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
  const errIn = id => e => { const p = $(id); p.textContent = e.message; p.hidden = false; };

  // Two presses instead of a browser dialog.
  const pressTwice = (key, btn, warn, onErr) => {
    if (armed.has(key)) { armed.delete(key); return true; }
    armed.add(key);
    const was = btn.textContent;
    btn.textContent = warn;
    setTimeout(() => { armed.delete(key); btn.textContent = was; }, 5000);
    onErr && onErr(null);
    return false;
  };

  $('invite-form').onsubmit = async ev => {
    ev.preventDefault();
    $('invite-err').hidden = true;
    $('invite-make').disabled = true;
    try {
      const r = await api('POST', '/invites', { note: $('invite-note').value.trim() });
      $('invite-qr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(r.qr_svg || '');
      $('invite-qr').hidden = !r.qr_svg;
      $('invite-link').textContent = r.url;
      $('invite-exp').textContent = `Works once, until ${when(r.expires_at)}.`;
      $('invite-copy').textContent = 'Copy link';
      $('invite-copy').onclick = async () => {
        await navigator.clipboard.writeText(r.url);
        $('invite-copy').textContent = 'Copied';
      };
      $('invite-new').hidden = false;
      $('invite-note').value = '';
      await loadInvites();
    } catch (e) { errIn('invite-err')(e); }
    finally { $('invite-make').disabled = false; }
  };

  const loadInvites = async () => {
    const all = me.is_admin ? await api('GET', '/admin/invites?open=1') : (await api('GET', '/me')).invites;
    const open = (all || []).filter(i => i.state === 'open');
    const ul = $('invites');
    ul.replaceChildren();
    $('invites-title').hidden = open.length === 0;
    for (const i of open) {
      const li = el('li');
      li.append(el('span', 'grow', i.note || `invite #${i.id}`));
      if (i.role === 'admin') li.append(el('span', 'tag', 'admin'));
      li.append(el('span', 'muted small', `until ${when(i.expires_at)}`));
      const rv = el('button', 'link danger', 'Revoke'); rv.type = 'button';
      rv.onclick = async () => {
        if (!pressTwice('inv' + i.id, rv, 'Press again to revoke')) return;
        try { await api('DELETE', '/invites/' + i.id); await loadInvites(); }
        catch (e) { errIn('invite-err')(e); }
      };
      li.append(rv);
      ul.append(li);
    }
  };

  // --------------------------------------------------------------- herd --

  // Searched and paged by the registrar: a pen of ten thousand loads like ten.
  const herd = { q: '', offset: 0, total: 0, seq: 0 };

  const herdCount = () => {
    const shown = $('members').children.length;
    $('herd-count').textContent = herd.q
      ? `${herd.total} match${herd.total === 1 ? '' : 'es'} for “${herd.q}”`
      : `${herd.total} in the pen${shown < herd.total ? `, showing ${shown}` : ''}`;
    $('herd-more').hidden = shown >= herd.total;
  };

  const memberRow = m => {
    const li = el('li');
    li.append(el('span', 'grow', m.handle));
    if (m.role !== 'member') li.append(el('span', 'tag', m.role));
    if (m.status === 'suspended') li.append(el('span', 'tag warn', 'suspended'));
    li.append(el('span', 'muted small', `${m.devices} device${m.devices === 1 ? '' : 's'}`));
    if (m.id === me.member.id) { li.append(el('span', 'here', 'you')); return li; }
    const act = (label, action, body, confirmText, after) => {
      const b = el('button', confirmText ? 'link danger' : 'link', label); b.type = 'button';
      b.onclick = async () => {
        if (confirmText && !pressTwice(action + m.id, b, confirmText)) return;
        b.disabled = true;
        $('herd-err').hidden = true;
        try {
          await api('POST', `/admin/members/${encodeURIComponent(m.handle)}/${action}`, body || {});
          after();
        } catch (e) { b.disabled = false; errIn('herd-err')(e); }
      };
      li.append(b);
    };
    const redraw = () => li.replaceWith(memberRow(m));
    // An admin can't act on the owner; the API refuses if tried.
    if (me.is_owner && m.role !== 'owner') {
      const to = m.role === 'admin' ? 'member' : 'admin';
      act(`Make ${to}`, 'role', { role: to }, null, () => { m.role = to; redraw(); });
    }
    if (m.status === 'suspended') act('Resume', 'resume', null, null, () => { m.status = 'active'; redraw(); });
    else act('Suspend', 'suspend', { reason: 'suspended from the home page' }, `Suspend ${m.handle}?`,
      () => { m.status = 'suspended'; redraw(); });
    act('Kick', 'kick', { reason: 'kicked from the home page' }, `Kick ${m.handle} for good?`,
      () => { li.remove(); herd.total--; herd.offset--; herdCount(); });
    return li;
  };

  const loadHerd = async (more) => {
    $('herd-err').hidden = true;
    if (!more) { herd.offset = 0; }
    const seq = ++herd.seq;   // a slow answer to an old search must not win
    const r = await api('GET', `/admin/herd?q=${encodeURIComponent(herd.q)}&offset=${herd.offset}`);
    if (seq !== herd.seq) return;
    if (!more) $('members').replaceChildren();
    for (const m of r.members) $('members').append(memberRow(m));
    herd.total = r.total;
    herd.offset += r.members.length;
    herdCount();
  };

  let searchTimer = null;
  $('herd-q').oninput = () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      herd.q = $('herd-q').value.trim().toLowerCase();
      loadHerd(false).catch(errIn('herd-err'));
    }, 250);
  };
  $('herd-form').onsubmit = ev => ev.preventDefault();
  $('herd-more').onclick = () => loadHerd(true).catch(errIn('herd-err'));

  const load = async () => {
    try { me = await api('GET', '/me'); render(); }
    catch (e) { $('whoami').textContent = 'Could not load your details: ' + e.message; return; }
    loadDirectory().catch(errIn('sites-err'));
    if (!me.devices) return;   // a server
    if (me.can_invite) { $('invite').hidden = false; loadInvites().catch(errIn('invite-err')); }
    if (me.is_admin) { $('herd').hidden = false; loadHerd().catch(errIn('herd-err')); }
  };
  load();
})();
