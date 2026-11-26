import { el, presenceBadge } from './dom.js';

export function renderOverview(doc, { me, herd, cachedSites, cachedAdminDevices }) {
  if (!me || !me.is_admin) return;
  const $ = id => doc.getElementById(id);
  $('overview').hidden = false;

  const totalMembers = herd.q ? herd.unfilteredTotal : herd.total;
  if (totalMembers !== null) {
    $('stat-members').textContent = String(totalMembers);
  }
  const membersSub = $('stat-members-sub');
  if (typeof me.owners === 'number' && me.owners > 0) {
    membersSub.textContent = me.owners === 1
      ? (me.is_owner ? '1 owner — appoint a backup' : '1 owner — no backup')
      : `${me.owners} owners`;
    membersSub.classList.toggle('warn-text', me.owners === 1);
  } else {
    membersSub.textContent = '';
    membersSub.classList.remove('warn-text');
  }

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
}

export function renderDirectory(doc, sites, nowMs = Date.now()) {
  const $ = id => doc.getElementById(id);
  const list = Array.isArray(sites) ? sites : [];
  $('sites').hidden = false;
  $('sites-err').hidden = true;
  const ul = $('directory');
  ul.replaceChildren();
  $('sites-empty').hidden = list.length > 0;
  for (const s of list) {
    const li = doc.createElement('li');
    const main = doc.createElement('div');
    main.className = 'site-main';
    const head = el(doc, 'div', 'site-head');
    const a = doc.createElement('a');
    a.href = 'https://' + s.name;
    a.rel = 'noopener';
    const hasPrivateLabel = Boolean(s.private && s.note);
    a.className = hasPrivateLabel ? 'site-link site-link-label' : 'site-link';
    a.textContent = hasPrivateLabel ? s.note : s.name;
    head.append(a);
    const badge = presenceBadge(doc, s.online, s.last_seen, nowMs);
    if (badge) head.append(badge);
    main.append(head);
    if (hasPrivateLabel) {
      const host = doc.createElement('div');
      host.className = 'muted small site-host';
      host.textContent = s.name;
      main.append(host);
    } else if (s.note) {
      const note = doc.createElement('div');
      note.className = 'muted small';
      note.textContent = s.note;
      main.append(note);
    }
    const by = doc.createElement('span');
    by.className = 'muted small';
    by.textContent = `run by ${s.member}`;
    li.append(main, by);
    ul.append(li);
  }
}
