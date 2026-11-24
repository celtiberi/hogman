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
  let isWork = false;
  let workApplied = false;
  const armed = new Set();

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

  const applyWorkTheme = () => {
    if (workApplied) return;
    workApplied = true;
    document.documentElement.dataset.theme = 'work';
    document.title = 'Portal · Hogman for Work';
    setFavicon('/work-favicon.svg');

    $('brand-icon').src = '/work-favicon.svg';
    $('brand-name').textContent = 'Hogman';
    $('brand-tag').hidden = false;

    $('nav-herd').textContent = 'Members';
    $('nav-host').textContent = 'Bridge';
    $('nav-docs').href = 'https://work.hogman.network/docs/';
    $('status-pill-text').textContent = 'Connected to private network \u00b7 HTTPS only';

    $('sites-host-link').textContent = 'Bridge a device or app \u2193';
    $('sites-empty').replaceChildren(
      document.createTextNode('No bridged devices or apps yet. Add one with '),
      Object.assign(document.createElement('code'), { textContent: '~/hogman-join share cooler-1 http://192.168.1.40 --background' }),
      document.createTextNode(' (see '),
      Object.assign(document.createElement('a'), { href: '#host', textContent: 'Bridge equipment or host an app' }),
      document.createTextNode(' below).')
    );

    $('device-card-hint').textContent = 'Generate a one-time link for another workstation (works once, expires in 1 hour). Use Get a share link for an always-on on-site bridge computer such as a Raspberry Pi or mini PC.';
    $('invite-note').placeholder = 'Who is it for? (e.g. Jordan \u2014 HVAC contractor, Store North)';

    $('herd-title').textContent = 'Members';
    $('herd-intro').textContent = 'Everyone with access to this pen. Suspending cuts off all their devices in ~2 seconds and is reversible. Removing ends membership permanently and retires their handle and site names.';
    $('herd-recovery').textContent = 'Someone lost every enrolled device? There is no account recovery: issue a new invite, restore their role, then remove the old account (demote an old owner to admin first).';

    $('host-title').textContent = 'Bridge equipment or host an app';
    $('host-guide-link').textContent = 'Bridging guide \u2192';
    $('host-guide-link').href = 'https://work.hogman.network/docs/share.html';
    $('host-intro').replaceChildren(
      document.createTextNode('Bridge a local LAN controller (plain HTTP is fine on the LAN) or an internal web app into this pen over standard HTTPS (port 443) with '),
      Object.assign(document.createElement('code'), { textContent: 'hogman-join' }),
      document.createTextNode(':')
    );
    $('host-code').textContent =
      '~/hogman-join share cooler-1 http://192.168.1.40 --background\n' +
      '~/hogman-join share inventory 8080 --note "Warehouse inventory"';

    const zoneSpan = document.createElement('span');
    zoneSpan.className = 'zone';
    zoneSpan.textContent = me ? me.zone : '<network>.pens.hogman.network';
    const hostUrl = document.createElement('code');
    hostUrl.append(document.createTextNode('https://cooler-1.'), zoneSpan);
    $('host-hint-1').replaceChildren(
      document.createTextNode('Everyone in the pen can then open '),
      hostUrl,
      document.createTextNode('. Add '),
      Object.assign(document.createElement('code'), { textContent: '--background' }),
      document.createTextNode(' to keep it running across reboots; '),
      Object.assign(document.createElement('code'), { textContent: '~/hogman-join share stop cooler-1' }),
      document.createTextNode(' takes it down and frees the name.')
    );
    $('host-hint-2').replaceChildren(
      document.createTextNode('Running on a dedicated on-site bridge computer (Raspberry Pi or mini PC)? Press '),
      Object.assign(document.createElement('em'), { textContent: 'Get a share link' }),
      document.createTextNode(' above and pass the link at the end: '),
      Object.assign(document.createElement('code'), { textContent: "./hogman-join share cooler-1 http://192.168.1.40 '<share link>' --background" }),
      document.createTextNode('. Remember: a pen hides devices from the internet, it does not patch firmware.')
    );

    $('foot-tagline').textContent = 'Hogman for Work \u00b7 Open source (AGPL-3.0)';
    const fl = $('foot-links');
    fl.replaceChildren();
    [
      ['work.hogman.network', 'https://work.hogman.network/'],
      ['Docs', 'https://work.hogman.network/docs/'],
      ['Bridging guide', 'https://work.hogman.network/docs/share.html'],
      ['Security', 'https://work.hogman.network/docs/security.html'],
      ['Policies', 'https://work.hogman.network/docs/policies.html'],
      ['FAQ', 'https://work.hogman.network/docs/faq.html'],
    ].forEach(([label, href], idx) => {
      if (idx > 0) fl.append(document.createTextNode(' \u00b7 '));
      const a = document.createElement('a');
      a.href = href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = label;
      fl.append(a);
    });
  };

  const render = () => {
    if (me.network && me.network.theme === 'work') {
      isWork = true;
      applyWorkTheme();
    }
    $('hello').textContent = isWork ? `Signed in as ${me.member.handle}` : `You're in, ${me.member.handle}.`;
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
        ? (isWork
            ? 'Share link: on the on-site bridge computer, open this link (it shows the command), or run ./hogman-join share NAME URL-or-PORT \'<this link>\' --background:'
            : 'Share link: on the computer that runs the thing you want to share, open this link (it shows the command), or run ./hogman-join share NAME PORT-or-FOLDER \'<this link>\':')
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
  const when = t => new Date(t * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
  const errIn = id => e => { const p = $(id); p.textContent = e.message; p.hidden = false; };

  // Two presses instead of a browser dialog.
  const pressTwice = (key, btn, warn, onErr) => {
    if (armed.has(key)) { armed.delete(key); btn.classList.remove('armed'); return true; }
    armed.add(key);
    const was = btn.textContent;
    btn.textContent = warn;
    btn.classList.add('armed');
    setTimeout(() => { armed.delete(key); btn.textContent = was; btn.classList.remove('armed'); }, 5000);
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
      : `${herd.total} ${isWork ? (herd.total === 1 ? 'member' : 'members') : 'in the pen'}${shown < herd.total ? `, showing ${shown}` : ''}`;
    $('herd-more').hidden = shown >= herd.total;
  };

  const soloOwner = () => { $('solo-owner').hidden = !(me.is_owner && me.owners === 1); };

  const closeOtherDrawers = except => {
    for (const row of $('members').children) {
      if (row === except) continue;
      const d = row.querySelector('.member-drawer');
      const b = row.querySelector('.manage-btn');
      if (d && !d.hidden) {
        d.hidden = true;
        if (b) { b.setAttribute('aria-expanded', 'false'); b.textContent = 'Manage'; }
      }
    }
  };

  const memberRow = m => {
    const li = el('li', 'member-row');
    const main = el('div', 'member-main');
    const idCol = el('div', 'member-id');
    idCol.append(el('span', 'member-name', m.handle));
    if (m.role !== 'member') idCol.append(el('span', 'tag', m.role));
    if (m.status === 'suspended') idCol.append(el('span', 'tag warn', 'suspended'));

    const rightCol = el('div', 'member-right');
    rightCol.append(el('span', 'muted small member-devices', `${m.devices} device${m.devices === 1 ? '' : 's'}`));
    main.append(idCol, rightCol);
    li.append(main);

    if (m.id === me.member.id) {
      rightCol.append(el('span', 'here', 'you'));
      return li;
    }
    // An admin can't act on an owner or another admin; the API refuses if tried.
    if (!me.is_owner && m.role !== 'member') return li;

    const drawer = el('div', 'member-drawer');
    drawer.hidden = true;

    const makeBtn = (label, danger, action, body, confirmText, after) => {
      const b = el('button', danger ? 'link danger' : 'link', label);
      b.type = 'button';
      b.onclick = async () => {
        if (confirmText && !pressTwice(action + m.id, b, confirmText)) return;
        b.disabled = true;
        $('herd-err').hidden = true;
        try {
          await api('POST', `/admin/members/${encodeURIComponent(m.handle)}/${action}`, body || {});
          after();
        } catch (e) { b.disabled = false; errIn('herd-err')(e); }
      };
      return b;
    };
    const redraw = () => li.replaceWith(memberRow(m));

    const accessGroup = el('div', 'drawer-group');
    accessGroup.append(el('span', 'drawer-label', 'Access'));
    if (m.status === 'suspended') {
      accessGroup.append(makeBtn('Resume', false, 'resume', null, null, () => { m.status = 'active'; redraw(); }));
    } else {
      accessGroup.append(makeBtn('Suspend', false, 'suspend',
        { reason: isWork ? 'suspended from the portal' : 'suspended from the home page' },
        `Suspend ${m.handle}?`, () => { m.status = 'suspended'; redraw(); }));
    }
    accessGroup.append(makeBtn(isWork ? 'Remove' : 'Kick', true, 'kick',
      { reason: isWork ? 'removed from the portal' : 'kicked from the home page' },
      isWork ? `Remove ${m.handle} permanently?` : `Kick ${m.handle} for good?`,
      () => { li.remove(); herd.total--; herd.offset--; herdCount(); }));
    drawer.append(accessGroup);

    const roleBtns = [];
    if (me.is_owner && m.role !== 'owner') {
      const to = m.role === 'admin' ? 'member' : 'admin';
      roleBtns.push(makeBtn(`Make ${to}`, false, 'role', { role: to }, null, () => { m.role = to; redraw(); }));
    }
    // A second owner is how a pen survives a lost laptop (D-16). Owners are
    // fully trusted: they can do everything, including demoting other owners.
    if (me.is_owner && m.role === 'admin') {
      roleBtns.push(makeBtn('Make owner', false, 'role', { role: 'owner' },
        `Make ${m.handle} an owner? Owners can do everything you can, including demoting you.`,
        () => { m.role = 'owner'; me.owners++; redraw(); soloOwner(); }));
    }
    if (me.is_owner && m.role === 'owner') {
      roleBtns.push(makeBtn('Make admin', false, 'role', { role: 'admin' },
        `Make ${m.handle} an admin instead of an owner?`,
        () => { m.role = 'admin'; me.owners--; redraw(); soloOwner(); }));
    }
    if (roleBtns.length) {
      const roleGroup = el('div', 'drawer-group');
      roleGroup.append(el('span', 'drawer-label', 'Role'), ...roleBtns);
      drawer.append(roleGroup);
    }

    const toggle = el('button', 'link manage-btn', 'Manage');
    toggle.type = 'button';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.onclick = () => {
      const opening = drawer.hidden;
      if (opening) closeOtherDrawers(li);
      drawer.hidden = !opening;
      toggle.setAttribute('aria-expanded', String(opening));
      toggle.textContent = opening ? 'Close' : 'Manage';
    };
    rightCol.append(toggle);
    li.append(drawer);
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
    if (me.is_admin) { $('herd').hidden = false; soloOwner(); loadHerd().catch(errIn('herd-err')); }
  };
  load();
})();
