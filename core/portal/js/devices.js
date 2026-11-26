import { copyToClipboard, el, formatTimestamp, presenceBadge, setQR, showErrorIn } from './dom.js';

export function renderMyDevices({ doc, api, pressTwice, onAfterDelete }, me) {
  const $ = id => doc.getElementById(id);
  if (!me.devices) return; // servers get a short answer and no device controls
  $('mine').hidden = false;
  const ul = $('devices');
  ul.replaceChildren();
  for (const d of me.devices) {
    const li = doc.createElement('li');
    const name = el(doc, 'span', 'grow', d.name);
    const kind = el(doc, 'span', 'tag', d.kind);
    li.append(name, kind);
    if (d.id === me.this_device.id) {
      li.append(el(doc, 'span', 'here', 'this device'));
    } else {
      const rm = el(doc, 'button', 'link danger', 'Remove');
      rm.type = 'button';
      rm.onclick = async () => {
        if (!pressTwice('mydev' + d.id, rm, `Remove ${d.name}?`)) return;
        rm.disabled = true;
        $('adderr').hidden = true;
        try {
          await api('DELETE', '/devices/' + d.id);
        } catch (e) {
          rm.disabled = false;
          showErrorIn(doc, 'adderr', e);
          return;
        }
        await onAfterDelete();
      };
      li.append(rm);
    }
    ul.append(li);
  }
}

export function createDeviceLinkAdder({
  doc,
  api,
  clipboard,
  setIntervalFn = (fn, ms) => setInterval(fn, ms),
  clearIntervalFn = id => clearInterval(id),
  now = () => Date.now(),
  getIsWork,
}) {
  const $ = id => doc.getElementById(id);
  let timer = null;

  async function add(kind) {
    $('adderr').hidden = true;
    $('add-personal').disabled = $('add-server').disabled = true;
    try {
      const r = await api('POST', '/devices', { kind });
      const isWork = getIsWork();
      // A share link is for a computer: no phone QR, and say what to run.
      setQR($('qr'), r.join_qr_svg, kind !== 'server');
      $('phone-line').hidden = kind === 'server' || isWork;
      $('computer-line').textContent = kind === 'server'
        ? (isWork
            ? 'Share link: on the on-site bridge computer, open this link (it shows the command), or run ~/hogman share NAME URL-or-PORT \'<this link>\':'
            : 'Share link: on the computer that runs the thing you want to share, open this link (it shows the command), or run ~/hogman share NAME PORT-or-FOLDER \'<this link>\':')
        : 'Computer: open this link on it and follow the steps:';
      $('linktext').textContent = r.join_link;
      $('newlink').hidden = false;
      $('copy').onclick = () => copyToClipboard(r.join_link, $('copy'), clipboard);
      $('copy').textContent = 'Copy link';
      clearIntervalFn(timer);
      const tick = () => {
        const left = r.expires_at - now() / 1000;
        if (left <= 0) {
          $('expires').textContent = 'Expired. Make a new one.';
          $('qr').classList.add('expired');
          clearIntervalFn(timer);
          return;
        }
        $('expires').textContent = `${kind === 'server' ? 'Share link. ' : ''}Works once, expires in ${Math.ceil(left / 60)} min.`;
      };
      $('qr').classList.remove('expired');
      tick();
      timer = setIntervalFn(tick, 15000);
    } catch (e) {
      showErrorIn(doc, 'adderr', e);
    } finally {
      $('add-personal').disabled = $('add-server').disabled = false;
    }
  }

  $('add-personal').onclick = () => add('personal');
  $('add-server').onclick = () => add('server');
  return { add };
}

export function createAdminDevicesSection({
  doc,
  api,
  pressTwice,
  getMe,
  onAfterDelete,
  onLoaded,
}) {
  const $ = id => doc.getElementById(id);
  let cached = [];
  const filter = { q: '', kind: 'all' };

  function render() {
    const me = getMe();
    const ul = $('all-devices-list');
    ul.replaceChildren();
    const { q, kind } = filter;
    const filtered = cached.filter(d => {
      if (kind !== 'all' && d.kind !== kind) return false;
      if (!q) return true;
      const hay = `${d.name || ''} ${d.member || ''} ${d.ipv4 || ''} ${d.kind || ''}`.toLowerCase();
      return hay.includes(q);
    });
    const onlineCount = cached.filter(d => d.online === true).length;
    const hasPresence = cached.some(d => typeof d.online === 'boolean');
    $('all-devices-count').textContent = hasPresence
      ? `${onlineCount} online · ${filtered.length}/${cached.length} shown`
      : `${filtered.length}${filtered.length === cached.length ? '' : '/' + cached.length} device${filtered.length === 1 ? '' : 's'}`;
    $('all-devices-empty').hidden = filtered.length > 0;

    for (const d of filtered) {
      const li = el(doc, 'li', 'device-row');
      const main = el(doc, 'div', 'device-main');
      const titleRow = el(doc, 'div', 'device-title');
      titleRow.append(el(doc, 'span', 'member-name', d.name || `device #${d.id}`));
      titleRow.append(el(doc, 'span', 'tag', d.kind || 'personal'));
      const badge = presenceBadge(doc, d.online, d.last_seen);
      if (badge) titleRow.append(badge);
      main.append(titleRow);

      const metaParts = [];
      if (d.member) metaParts.push(d.member);
      if (d.ipv4) metaParts.push(d.ipv4);
      if (d.created_at) metaParts.push(`added ${formatTimestamp(d.created_at)}`);
      main.append(el(doc, 'div', 'muted small device-meta', metaParts.join(' · ')));

      const right = el(doc, 'div', 'device-right');
      if (me && me.this_device && d.id === me.this_device.id) {
        right.append(el(doc, 'span', 'here', 'this device'));
      } else {
        const rm = el(doc, 'button', 'link danger', 'Remove');
        rm.type = 'button';
        rm.onclick = async () => {
          if (!pressTwice('admdev' + d.id, rm, `Remove ${d.name}?`)) return;
          rm.disabled = true;
          $('all-devices-err').hidden = true;
          try {
            await api('DELETE', '/devices/' + d.id);
          } catch (e) {
            rm.disabled = false;
            showErrorIn(doc, 'all-devices-err', e);
            return;
          }
          await onAfterDelete();
        };
        right.append(rm);
      }
      li.append(main, right);
      ul.append(li);
    }
  }

  async function load() {
    $('all-devices-err').hidden = true;
    const ds = await api('GET', '/admin/devices');
    cached = Array.isArray(ds) ? ds : [];
    render();
    onLoaded(cached);
  }

  $('all-devices-q').oninput = () => {
    filter.q = $('all-devices-q').value.trim().toLowerCase();
    render();
  };
  $('all-devices-kind').addEventListener('click', ev => {
    const btn = ev.target.closest('button[data-kind]');
    if (!btn) return;
    filter.kind = btn.dataset.kind;
    $('all-devices-kind').querySelectorAll('button[data-kind]').forEach(b => {
      const active = b === btn;
      b.classList.toggle('active', active);
      b.setAttribute('aria-pressed', String(active));
    });
    render();
  });
  $('all-devices-refresh').onclick = () => load().catch(e => showErrorIn(doc, 'all-devices-err', e));

  return { load, render, getCached: () => cached };
}
