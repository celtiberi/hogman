import { copyToClipboard, el, formatTimestamp, setQR, showErrorIn } from './dom.js';

export function createInvitesSection({ doc, api, pressTwice, clipboard, getMe }) {
  const $ = id => doc.getElementById(id);

  async function load() {
    const me = getMe();
    const all = me.is_admin ? await api('GET', '/admin/invites?open=1') : (await api('GET', '/me')).invites;
    const open = (all || []).filter(i => i.state === 'open');
    const ul = $('invites');
    ul.replaceChildren();
    $('invites-title').hidden = open.length === 0;
    for (const i of open) {
      const li = el(doc, 'li');
      li.append(el(doc, 'span', 'grow', i.note || `invite #${i.id}`));
      if (i.role === 'admin') li.append(el(doc, 'span', 'tag', 'admin'));
      li.append(el(doc, 'span', 'muted small', `until ${formatTimestamp(i.expires_at)}`));
      const rv = el(doc, 'button', 'link danger', 'Revoke');
      rv.type = 'button';
      rv.onclick = async () => {
        if (!pressTwice('inv' + i.id, rv, 'Press again to revoke')) return;
        rv.disabled = true;
        $('invite-err').hidden = true;
        try {
          await api('DELETE', '/invites/' + i.id);
        } catch (e) {
          rv.disabled = false;
          showErrorIn(doc, 'invite-err', e);
          return;
        }
        await load().catch(e => showErrorIn(doc, 'invite-err', e));
      };
      li.append(rv);
      ul.append(li);
    }
  }

  $('invite-form').onsubmit = async ev => {
    ev.preventDefault();
    $('invite-err').hidden = true;
    $('invite-make').disabled = true;
    try {
      const r = await api('POST', '/invites', { note: $('invite-note').value.trim() });
      setQR($('invite-qr'), r.qr_svg, true);
      $('invite-link').textContent = r.url;
      $('invite-exp').textContent = `Works once, until ${formatTimestamp(r.expires_at)}.`;
      $('invite-copy').textContent = 'Copy link';
      $('invite-copy').onclick = () => copyToClipboard(r.url, $('invite-copy'), clipboard);
      $('invite-new').hidden = false;
      $('invite-note').value = '';
      await load();
    } catch (e) {
      showErrorIn(doc, 'invite-err', e);
    } finally {
      $('invite-make').disabled = false;
    }
  };

  return { load };
}

export function createHerdSection({
  doc,
  api,
  pressTwice,
  getMe,
  getIsWork,
  onAfterKick,
  onAuditChanged,
  onOverviewChanged,
}) {
  const $ = id => doc.getElementById(id);
  const herd = { q: '', offset: 0, total: 0, unfilteredTotal: null, seq: 0 };

  function updateCount() {
    const shown = $('members').children.length;
    const isWork = getIsWork();
    $('herd-count').textContent = herd.q
      ? `${herd.total} match${herd.total === 1 ? '' : 'es'} for “${herd.q}”`
      : `${herd.total} ${isWork ? (herd.total === 1 ? 'member' : 'members') : 'in the pen'}${shown < herd.total ? `, showing ${shown}` : ''}`;
    $('herd-more').hidden = shown >= herd.total;
  }

  function updateSoloOwner() {
    const me = getMe();
    $('solo-owner').hidden = !(me.is_owner && me.owners === 1);
  }

  function closeOtherDrawers(except) {
    for (const row of $('members').children) {
      if (row === except) continue;
      const d = row.querySelector('.member-drawer');
      const b = row.querySelector('.manage-btn');
      if (d && !d.hidden) {
        d.hidden = true;
        if (b) {
          b.setAttribute('aria-expanded', 'false');
          b.textContent = 'Manage';
        }
      }
    }
  }

  function memberRow(m) {
    const me = getMe();
    const isWork = getIsWork();
    const li = el(doc, 'li', 'member-row');
    const main = el(doc, 'div', 'member-main');
    const idCol = el(doc, 'div', 'member-id');
    idCol.append(el(doc, 'span', 'member-name', m.handle));
    if (m.role !== 'member') idCol.append(el(doc, 'span', 'tag', m.role));
    if (m.status === 'suspended') idCol.append(el(doc, 'span', 'tag warn', 'suspended'));

    const rightCol = el(doc, 'div', 'member-right');
    rightCol.append(el(doc, 'span', 'muted small member-devices', `${m.devices} device${m.devices === 1 ? '' : 's'}`));
    main.append(idCol, rightCol);
    li.append(main);

    if (m.id === me.member.id) {
      rightCol.append(el(doc, 'span', 'here', 'you'));
      return li;
    }
    // An admin can't act on an owner or another admin; the API refuses if tried.
    if (!me.is_owner && m.role !== 'member') return li;

    const drawer = el(doc, 'div', 'member-drawer');
    drawer.hidden = true;

    const makeBtn = (label, danger, action, body, confirmText, after) => {
      const b = el(doc, 'button', danger ? 'link danger' : 'link', label);
      b.type = 'button';
      b.onclick = async () => {
        if (confirmText && !pressTwice(action + m.id, b, confirmText)) return;
        b.disabled = true;
        $('herd-err').hidden = true;
        try {
          await api('POST', `/admin/members/${encodeURIComponent(m.handle)}/${action}`, body || {});
          after();
        } catch (e) {
          b.disabled = false;
          showErrorIn(doc, 'herd-err', e);
        }
      };
      return b;
    };
    const redraw = () => li.replaceWith(memberRow(m));

    const accessGroup = el(doc, 'div', 'drawer-group');
    accessGroup.append(el(doc, 'span', 'drawer-label', 'Access'));
    if (m.status === 'suspended') {
      accessGroup.append(makeBtn('Resume', false, 'resume', null, null, () => {
        m.status = 'active';
        redraw();
        onAuditChanged();
      }));
    } else {
      accessGroup.append(makeBtn('Suspend', false, 'suspend',
        { reason: isWork ? 'suspended from the portal' : 'suspended from the home page' },
        `Suspend ${m.handle}?`, () => {
          m.status = 'suspended';
          redraw();
          onAuditChanged();
        }));
    }
    accessGroup.append(makeBtn(isWork ? 'Remove' : 'Kick', true, 'kick',
      { reason: isWork ? 'removed from the portal' : 'kicked from the home page' },
      isWork ? `Remove ${m.handle} permanently?` : `Kick ${m.handle} for good?`,
      () => {
        li.remove();
        herd.total = Math.max(0, herd.total - 1);
        herd.offset = Math.max(0, herd.offset - 1);
        if (herd.unfilteredTotal !== null) {
          herd.unfilteredTotal = Math.max(0, herd.unfilteredTotal - 1);
        }
        updateCount();
        onOverviewChanged();
        onAfterKick();
      }));
    drawer.append(accessGroup);

    const roleBtns = [];
    if (me.is_owner && m.role !== 'owner') {
      const to = m.role === 'admin' ? 'member' : 'admin';
      roleBtns.push(makeBtn(`Make ${to}`, false, 'role', { role: to }, null, () => {
        m.role = to;
        redraw();
        onAuditChanged();
      }));
    }
    // A second owner keeps the pen recoverable if one device is lost. Owners are
    // fully trusted: they can do everything, including demoting other owners.
    if (me.is_owner && m.role === 'admin') {
      roleBtns.push(makeBtn('Make owner', false, 'role', { role: 'owner' },
        `Make ${m.handle} an owner? Owners can do everything you can, including demoting you.`,
        () => {
          m.role = 'owner';
          me.owners++;
          redraw();
          updateSoloOwner();
          onOverviewChanged();
          onAuditChanged();
        }));
    }
    if (me.is_owner && m.role === 'owner') {
      roleBtns.push(makeBtn('Make admin', false, 'role', { role: 'admin' },
        `Make ${m.handle} an admin instead of an owner?`,
        () => {
          m.role = 'admin';
          me.owners--;
          redraw();
          updateSoloOwner();
          onOverviewChanged();
          onAuditChanged();
        }));
    }
    if (roleBtns.length) {
      const roleGroup = el(doc, 'div', 'drawer-group');
      roleGroup.append(el(doc, 'span', 'drawer-label', 'Role'), ...roleBtns);
      drawer.append(roleGroup);
    }

    const toggle = el(doc, 'button', 'link manage-btn', 'Manage');
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
  }

  async function load(more = false) {
    $('herd-err').hidden = true;
    if (!more) herd.offset = 0;
    const seq = ++herd.seq; // a slow answer to an old search must not win
    const r = await api('GET', `/admin/herd?q=${encodeURIComponent(herd.q)}&offset=${herd.offset}`);
    if (seq !== herd.seq) return;
    if (!more) $('members').replaceChildren();
    for (const m of r.members) $('members').append(memberRow(m));
    herd.total = r.total;
    if (!herd.q) herd.unfilteredTotal = r.total;
    herd.offset += r.members.length;
    updateCount();
    onOverviewChanged();
  }

  let searchTimer = null;
  $('herd-q').oninput = () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      herd.q = $('herd-q').value.trim().toLowerCase();
      load(false).catch(e => showErrorIn(doc, 'herd-err', e));
    }, 250);
  };
  $('herd-form').onsubmit = ev => ev.preventDefault();
  $('herd-more').onclick = () => load(true).catch(e => showErrorIn(doc, 'herd-err', e));

  return { load, updateSoloOwner, getState: () => herd };
}

const AUDIT_ACTION_LABELS = {
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
  'pen.delete.token': 'delete link created',
};

export function createAuditSection({ doc, api }) {
  const $ = id => doc.getElementById(id);
  let cached = [];
  let shown = 25;

  function render() {
    const ul = $('audit-list');
    ul.replaceChildren();
    const slice = cached.slice(0, shown);
    $('audit-count').textContent = cached.length
      ? `${slice.length}${slice.length < cached.length ? ' of ' + cached.length : ''} event${cached.length === 1 ? '' : 's'}`
      : '';
    $('audit-empty').hidden = cached.length > 0;
    $('audit-more').hidden = slice.length >= cached.length;

    for (const a of slice) {
      const li = el(doc, 'li', 'audit-row');
      const main = el(doc, 'div', 'audit-main');
      const head = el(doc, 'div', 'audit-head');
      const rawAct = a.action || 'event';
      const label = AUDIT_ACTION_LABELS[rawAct] || rawAct;
      const isWarn = rawAct.includes('kick') || rawAct.includes('suspend') || rawAct.includes('revoke') || rawAct.includes('reject') || rawAct.includes('delete');
      head.append(el(doc, 'span', isWarn ? 'tag warn' : 'tag', label));
      const summary = a.target ? `${a.actor || 'system'} → ${a.target}` : (a.actor || 'system');
      head.append(el(doc, 'span', 'audit-summary', summary));
      main.append(head);
      if (a.detail) {
        main.append(el(doc, 'div', 'muted small audit-detail', a.detail));
      }
      const ts = el(doc, 'span', 'muted small audit-time', a.at ? formatTimestamp(a.at) : '');
      li.append(main, ts);
      ul.append(li);
    }
  }

  async function load() {
    $('audit-err').hidden = true;
    const log = await api('GET', '/admin/audit?limit=250');
    cached = Array.isArray(log) ? log : [];
    render();
  }

  $('audit-more').onclick = () => {
    shown += 25;
    render();
  };
  $('audit-refresh').onclick = () => load().catch(e => showErrorIn(doc, 'audit-err', e));

  return { load, render };
}
