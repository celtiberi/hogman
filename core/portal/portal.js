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
  let cachedSites = [];
  let cachedAdminDevices = [];
  let cachedAudit = [];
  let adminDevicesFilter = { q: '', kind: 'all' };
  let auditShown = 25;
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
    $('stat-sites-label').textContent = 'Bridges & apps';
    $('all-devices-intro').textContent = 'Every enrolled staff workstation and bridge server across this pen. Remove a lost laptop or retired bridge at any time.';
    $('audit-intro').textContent = 'Audit log of member onboarding, offboarding, role changes, device enrollments, and bridged services in this pen.';
    $('status-pill-text').textContent = 'Connected to private network \u00b7 HTTPS only';

    $('sites-host-link').textContent = 'Bridge a device or app \u2193';
    $('sites-empty').replaceChildren(
      document.createTextNode('No bridged devices or apps yet. Follow the '),
      Object.assign(document.createElement('a'), {
        href: 'https://work.hogman.network/docs/share.html',
        target: '_blank',
        rel: 'noopener noreferrer',
        textContent: 'Bridging guide',
      }),
      document.createTextNode(' to bridge an existing LAN controller or internal web app into this pen.')
    );

    $('device-card-hint').textContent = 'Generate a one-time link for another workstation (works once, expires in 1 hour). Use Get a share link for an always-on on-site bridge computer such as a Raspberry Pi or mini PC.';
    $('invite-note').placeholder = 'Who is it for? (e.g. Jordan \u2014 HVAC contractor, Store North)';

    $('herd-title').textContent = 'Members';
    $('herd-intro').textContent = 'Everyone with access to this pen. Suspending cuts off all their devices in ~2 seconds and is reversible. Removing ends membership permanently and retires their handle and site names.';
    $('herd-recovery').textContent = 'Someone lost every enrolled device? There is no account recovery: issue a new invite, restore their role, then remove the old account (demote an old owner to admin first).';

    $('host-title').textContent = 'Bridge equipment or host an app';
    $('host-guide-link').textContent = 'Read the bridging guide \u2192';
    $('host-guide-link').href = 'https://work.hogman.network/docs/share.html';
    $('host-intro').textContent = 'Bridge an existing LAN controller (plain HTTP is fine on the LAN) or an internal web app into this pen over standard HTTPS (port 443). Read the bridging guide for step-by-step instructions on workstations, dedicated on-site bridge machines, and private site names.';
    $('host-hint-ctlog').replaceChildren(
      document.createTextNode('Bridged site names appear in public certificate logs (traffic stays private) — see the guide for '),
      Object.assign(document.createElement('code'), { textContent: '--private-name' }),
      document.createTextNode('. A pen hides devices from the internet; it does not patch firmware.')
    );

    $('foot-tagline').textContent = 'Hogman for Work \u00b7 Open source (AGPL-3.0)';
    const fl = $('foot-links');
    fl.replaceChildren();
    [
      ['work.hogman.network', 'https://work.hogman.network/'],
      ['Docs', 'https://work.hogman.network/docs/'],
      ['Bridging guide', 'https://work.hogman.network/docs/share.html'],
      ['Security', 'https://work.hogman.network/docs/security.html'],
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

  const relativeTime = iso => {
    if (!iso) return '';
    const ms = Date.parse(iso);
    if (Number.isNaN(ms)) return '';
    const diff = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    const days = Math.floor(diff / 86400);
    if (days < 30) return `${days}d ago`;
    return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  };

  const presenceBadge = (online, lastSeen) => {
    if (typeof online !== 'boolean') return null;
    const span = el('span', online ? 'presence online' : 'presence offline');
    const dot = el('span', 'presence-dot');
    dot.setAttribute('aria-hidden', 'true');
    span.append(dot);
    if (online) {
      span.append(document.createTextNode('online'));
    } else {
      const ago = relativeTime(lastSeen);
      span.append(document.createTextNode(ago ? `offline · ${ago}` : 'offline'));
    }
    return span;
  };

  const renderOverview = () => {
    if (!me || !me.is_admin) return;
    $('overview').hidden = false;

    const totalMembers = herd.q ? null : herd.total;
    if (totalMembers !== null) {
      $('stat-members').textContent = String(totalMembers);
    }
    const owners = me.owners || 0;
    const membersSub = $('stat-members-sub');
    membersSub.textContent = owners === 1
      ? '1 owner — appoint a backup'
      : `${owners} owners`;
    membersSub.classList.toggle('warn-text', owners === 1);

    const devs = cachedAdminDevices || [];
    const hasPresence = devs.some(d => typeof d.online === 'boolean');
    if (hasPresence) {
      const online = devs.filter(d => d.online === true).length;
      $('stat-devices').textContent = `${online} / ${devs.length}`;
      $('stat-devices-sub').textContent = 'online now';
    } else {
      const personal = devs.filter(d => d.kind === 'personal').length;
      const servers = devs.filter(d => d.kind === 'server').length;
      $('stat-devices').textContent = String(devs.length);
      $('stat-devices-sub').textContent = `${personal} personal · ${servers} server${servers === 1 ? '' : 's'}`;
    }

    const sites = cachedSites || [];
    const sitePresence = sites.some(s => typeof s.online === 'boolean');
    if (sitePresence) {
      const up = sites.filter(s => s.online === true).length;
      $('stat-sites').textContent = `${up} / ${sites.length}`;
      $('stat-sites-sub').textContent = 'reachable now';
    } else {
      $('stat-sites').textContent = String(sites.length);
      $('stat-sites-sub').textContent = 'HTTPS (:443) only';
    }

    const b = me.billing;
    const planLabel = b && b.plan
      ? (b.plan === 'work' ? 'Work' : (b.plan === 'personal' ? 'Personal' : (b.plan === 'free' ? 'Free' : String(b.plan))))
      : '';
    $('stat-plan-label').textContent = planLabel ? 'Plan & status' : 'Status';
    const planSub = $('stat-plan-sub');
    planSub.classList.remove('warn-text');
    if (b && b.state === 'grace') {
      $('stat-plan').textContent = planLabel ? `${planLabel} · Grace` : 'Grace period';
      planSub.textContent = b.grace_until
        ? `Sleeps ${String(b.grace_until).slice(0, 10)}`
        : 'Renewal needed';
      planSub.classList.add('warn-text');
    } else if (b && b.state === 'renew_only') {
      $('stat-plan').textContent = 'Renewal window';
      planSub.textContent = 'Temporary wake';
      planSub.classList.add('warn-text');
    } else if (b && b.state === 'active') {
      $('stat-plan').textContent = planLabel || 'Active';
      planSub.textContent = b.paid_until
        ? `Paid until ${String(b.paid_until).slice(0, 10)}`
        : 'Current';
    } else {
      $('stat-plan').textContent = planLabel || 'Active';
      planSub.textContent = 'Private HTTPS only';
    }
  };

  const loadDirectory = async () => {
    const sites = await api('GET', '/directory');
    cachedSites = Array.isArray(sites) ? sites : [];
    $('sites').hidden = false;
    $('sites-err').hidden = true;
    const ul = $('directory');
    ul.replaceChildren();
    $('sites-empty').hidden = cachedSites.length > 0;
    for (const s of cachedSites) {
      const li = document.createElement('li');
      const main = document.createElement('div');
      main.className = 'site-main';
      const head = el('div', 'site-head');
      const a = document.createElement('a');
      a.href = 'https://' + s.name;
      a.rel = 'noopener';
      const hasPrivateLabel = Boolean(s.private && s.note);
      a.className = hasPrivateLabel ? 'site-link site-link-label' : 'site-link';
      a.textContent = hasPrivateLabel ? s.note : s.name;
      head.append(a);
      const badge = presenceBadge(s.online, s.last_seen);
      if (badge) head.append(badge);
      main.append(head);
      if (hasPrivateLabel) {
        const host = document.createElement('div');
        host.className = 'muted small site-host';
        host.textContent = s.name;
        main.append(host);
      } else if (s.note) {
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
    renderOverview();
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
            ? 'Share link: on the on-site bridge computer, open this link (it shows the command), or run ./hogman share NAME URL-or-PORT \'<this link>\' --background:'
            : 'Share link: on the computer that runs the thing you want to share, open this link (it shows the command), or run ./hogman share NAME PORT-or-FOLDER \'<this link>\':')
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
      () => { li.remove(); herd.total--; herd.offset--; herdCount(); renderOverview(); loadAdminDevices().catch(() => {}); loadAudit().catch(() => {}); }));
    drawer.append(accessGroup);

    const roleBtns = [];
    if (me.is_owner && m.role !== 'owner') {
      const to = m.role === 'admin' ? 'member' : 'admin';
      roleBtns.push(makeBtn(`Make ${to}`, false, 'role', { role: to }, null, () => { m.role = to; redraw(); loadAudit().catch(() => {}); }));
    }
    // A second owner is how a pen survives a lost laptop (D-16). Owners are
    // fully trusted: they can do everything, including demoting other owners.
    if (me.is_owner && m.role === 'admin') {
      roleBtns.push(makeBtn('Make owner', false, 'role', { role: 'owner' },
        `Make ${m.handle} an owner? Owners can do everything you can, including demoting you.`,
        () => { m.role = 'owner'; me.owners++; redraw(); soloOwner(); renderOverview(); loadAudit().catch(() => {}); }));
    }
    if (me.is_owner && m.role === 'owner') {
      roleBtns.push(makeBtn('Make admin', false, 'role', { role: 'admin' },
        `Make ${m.handle} an admin instead of an owner?`,
        () => { m.role = 'admin'; me.owners--; redraw(); soloOwner(); renderOverview(); loadAudit().catch(() => {}); }));
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
    renderOverview();
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

  // ------------------------------------------------------- all devices --

  const renderAdminDevices = () => {
    const ul = $('all-devices-list');
    ul.replaceChildren();
    const q = adminDevicesFilter.q;
    const kind = adminDevicesFilter.kind;
    const filtered = cachedAdminDevices.filter(d => {
      if (kind !== 'all' && d.kind !== kind) return false;
      if (!q) return true;
      const hay = `${d.name || ''} ${d.member || ''} ${d.ipv4 || ''} ${d.kind || ''}`.toLowerCase();
      return hay.includes(q);
    });
    const onlineCount = cachedAdminDevices.filter(d => d.online === true).length;
    const hasPresence = cachedAdminDevices.some(d => typeof d.online === 'boolean');
    $('all-devices-count').textContent = hasPresence
      ? `${onlineCount} online · ${filtered.length}/${cachedAdminDevices.length} shown`
      : `${filtered.length}${filtered.length === cachedAdminDevices.length ? '' : '/' + cachedAdminDevices.length} device${filtered.length === 1 ? '' : 's'}`;
    $('all-devices-empty').hidden = filtered.length > 0;

    for (const d of filtered) {
      const li = el('li', 'device-row');
      const main = el('div', 'device-main');
      const titleRow = el('div', 'device-title');
      titleRow.append(el('span', 'member-name', d.name || `device #${d.id}`));
      titleRow.append(el('span', 'tag', d.kind || 'personal'));
      const badge = presenceBadge(d.online, d.last_seen);
      if (badge) titleRow.append(badge);
      main.append(titleRow);

      const metaParts = [];
      if (d.member) metaParts.push(d.member);
      if (d.ipv4) metaParts.push(d.ipv4);
      if (d.created_at) metaParts.push(`added ${when(d.created_at)}`);
      main.append(el('div', 'muted small device-meta', metaParts.join(' · ')));

      const right = el('div', 'device-right');
      if (me && me.this_device && d.id === me.this_device.id) {
        right.append(el('span', 'here', 'this device'));
      } else {
        const rm = el('button', 'link danger', 'Remove');
        rm.type = 'button';
        rm.onclick = async () => {
          if (!pressTwice('admdev' + d.id, rm, `Remove ${d.name}?`)) return;
          rm.disabled = true;
          $('all-devices-err').hidden = true;
          try {
            await api('DELETE', '/devices/' + d.id);
            await Promise.all([loadAdminDevices(), loadDirectory(), loadAudit()]);
          } catch (e) {
            rm.disabled = false;
            errIn('all-devices-err')(e);
          }
        };
        right.append(rm);
      }
      li.append(main, right);
      ul.append(li);
    }
  };

  const loadAdminDevices = async () => {
    $('all-devices-err').hidden = true;
    const ds = await api('GET', '/admin/devices');
    cachedAdminDevices = Array.isArray(ds) ? ds : [];
    renderAdminDevices();
    renderOverview();
  };

  $('all-devices-q').oninput = () => {
    adminDevicesFilter.q = $('all-devices-q').value.trim().toLowerCase();
    renderAdminDevices();
  };
  $('all-devices-kind').addEventListener('click', ev => {
    const btn = ev.target.closest('button[data-kind]');
    if (!btn) return;
    adminDevicesFilter.kind = btn.dataset.kind;
    $('all-devices-kind').querySelectorAll('button[data-kind]').forEach(b => {
      const active = b === btn;
      b.classList.toggle('active', active);
      b.setAttribute('aria-pressed', String(active));
    });
    renderAdminDevices();
  });
  $('all-devices-refresh').onclick = () => loadAdminDevices().catch(errIn('all-devices-err'));

  // ------------------------------------------------------------- audit --

  const auditActionLabels = {
    'member.add': 'member added',
    'member.role': 'role changed',
    'member.suspend': 'suspended',
    'member.resume': 'resumed',
    'member.kick': 'removed',
    'invite.mint': 'invite created',
    'invite.revoke': 'invite revoked',
    'invite.redeem': 'invite redeemed',
    'device.key': 'device link created',
    'device.join': 'device joined',
    'device.remove': 'device removed',
    'device.gone': 'device left',
    'device.reject': 'device rejected',
    'name.claim': 'site added',
    'name.release': 'site removed',
    'acme.eab': 'cert fallback issued',
  };

  const renderAudit = () => {
    const ul = $('audit-list');
    ul.replaceChildren();
    const slice = cachedAudit.slice(0, auditShown);
    $('audit-count').textContent = cachedAudit.length
      ? `${slice.length}${slice.length < cachedAudit.length ? ' of ' + cachedAudit.length : ''} event${cachedAudit.length === 1 ? '' : 's'}`
      : '';
    $('audit-empty').hidden = cachedAudit.length > 0;
    $('audit-more').hidden = slice.length >= cachedAudit.length;

    for (const a of slice) {
      const li = el('li', 'audit-row');
      const main = el('div', 'audit-main');
      const head = el('div', 'audit-head');
      const rawAct = a.action || 'event';
      const label = auditActionLabels[rawAct] || rawAct;
      const isWarn = rawAct.includes('kick') || rawAct.includes('suspend') || rawAct.includes('revoke') || rawAct.includes('reject');
      const actTag = el('span', isWarn ? 'tag warn' : 'tag', label);
      head.append(actTag);
      const summary = a.target ? `${a.actor || 'system'} → ${a.target}` : (a.actor || 'system');
      head.append(el('span', 'audit-summary', summary));
      main.append(head);
      if (a.detail) {
        main.append(el('div', 'muted small audit-detail', a.detail));
      }
      const ts = el('span', 'muted small audit-time', a.at ? when(a.at) : '');
      li.append(main, ts);
      ul.append(li);
    }
  };

  const loadAudit = async () => {
    $('audit-err').hidden = true;
    const log = await api('GET', '/admin/audit?limit=250');
    cachedAudit = Array.isArray(log) ? log : [];
    renderAudit();
  };

  $('audit-more').onclick = () => { auditShown += 25; renderAudit(); };
  $('audit-refresh').onclick = () => loadAudit().catch(errIn('audit-err'));

  const renderBillingBanner = (st) => {
    const el = $('billing-banner');
    if (!el) return;
    if (!st || (st.state !== 'grace' && st.state !== 'renew_only')) { el.hidden = true; return; }
    const p = document.createElement('p');
    const strong = document.createElement('strong');
    const appendRenewButton = () => {
      if (!st.can_renew) return;
      p.append(document.createTextNode(' '));
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'link';
      btn.textContent = 'Renew now';
      btn.onclick = async () => {
        btn.disabled = true;
        try {
          const r = await api('POST', '/billing/renew-token', {});
          if (typeof r.url === 'string' && r.url.startsWith('https://')) {
            window.open(r.url, '_blank', 'noopener,noreferrer');
          }
        } catch (e) {
          showError(e);
        } finally {
          btn.disabled = false;
        }
      };
      p.append(btn);
    };

    if (st.state === 'renew_only') {
      strong.textContent = 'Woken for renewal: ';
      p.append(strong);
      let until = 'shortly';
      if (st.wake_until) {
        const d = new Date(st.wake_until);
        if (!Number.isNaN(d.getTime())) {
          const mins = Math.max(0, Math.ceil((d.getTime() - Date.now()) / 60000));
          until = `${d.toISOString().slice(11, 16)} UTC (${mins} min left)`;
        }
      }
      p.append(document.createTextNode(
        `this pen is temporarily awake for billing renewal until ${until}. ` +
        'Shares, invites, devices, and access for other members are unavailable until the pen is renewed. ' +
        'Once payment completes, normal access restores automatically.'
      ));
      appendRenewButton();
      el.replaceChildren(p);
      el.hidden = false;
      return;
    }

    strong.textContent = 'Renewal needed: ';
    p.append(strong);
    let until = 'soon';
    if (st.grace_until) {
      const d = new Date(st.grace_until);
      if (!Number.isNaN(d.getTime())) {
        const days = Math.max(0, Math.ceil((d.getTime() - Date.now()) / 86400000));
        until = `${d.toISOString().slice(0, 10)} (${days} day${days === 1 ? '' : 's'} left)`;
      }
    }
    if (me && me.is_admin) {
      p.append(document.createTextNode(
        `this pen is in its 30-day grace period and will go to sleep on ${until}. ` +
        'Any owner or admin can renew from this page for a fresh year (an admin who pays becomes an owner).'
      ));
      appendRenewButton();
    } else {
      p.append(document.createTextNode(
        `this pen is in its 30-day grace period and will go to sleep on ${until}. ` +
        'Ask an owner or admin to renew it from this page.'
      ));
    }
    el.replaceChildren(p);
    el.hidden = false;
  };

  const load = async () => {
    try { me = await api('GET', '/me'); render(); renderBillingBanner(me.billing); }
    catch (e) { $('whoami').textContent = 'Could not load your details: ' + e.message; return; }
    if (me.billing && me.billing.state === 'renew_only') {
      ['overview', 'sites', 'mine', 'invite', 'herd', 'all-devices', 'audit', 'host'].forEach(id => { const s = $(id); if (s) s.hidden = true; });
      return;
    }
    loadDirectory().catch(errIn('sites-err'));
    if (!me.devices) return;   // a server
    if (me.can_invite) {
      $('invite').hidden = false;
      $('nav-invite').hidden = false;
      loadInvites().catch(errIn('invite-err'));
    }
    if (me.is_admin) {
      $('herd').hidden = false;
      $('nav-herd').hidden = false;
      $('all-devices').hidden = false;
      $('nav-all-devices').hidden = false;
      $('audit').hidden = false;
      $('nav-audit').hidden = false;
      soloOwner();
      renderOverview();
      loadHerd().catch(errIn('herd-err'));
      loadAdminDevices().catch(errIn('all-devices-err'));
      loadAudit().catch(errIn('audit-err'));
    }
  };
  load();
})();
