import { el } from './dom.js';

export function renderBillingBanner({ doc, api, navigate, now = () => Date.now() }, me, st) {
  const banner = doc.getElementById('billing-banner');
  if (!banner) return;
  if (!st || (st.state !== 'grace' && st.state !== 'renew_only')) {
    banner.hidden = true;
    return;
  }

  const p = doc.createElement('p');
  const errP = el(doc, 'p', 'error');
  errP.id = 'billing-err';
  errP.hidden = true;
  const strong = doc.createElement('strong');

  const appendRenewButton = () => {
    if (!st.can_renew) return;
    p.append(doc.createTextNode(' '));
    const btn = doc.createElement('button');
    btn.type = 'button';
    btn.className = 'link';
    btn.textContent = 'Renew now';
    btn.onclick = async () => {
      btn.disabled = true;
      errP.hidden = true;
      try {
        const r = await api('POST', '/billing/renew-token', {});
        if (typeof r.url === 'string' && r.url.startsWith('https://')) {
          navigate(r.url);
          return;
        }
        throw new Error('Renewal link was not returned.');
      } catch (e) {
        errP.textContent = e.message;
        errP.hidden = false;
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
        const mins = Math.max(0, Math.ceil((d.getTime() - now()) / 60000));
        until = `${d.toISOString().slice(11, 16)} UTC (${mins} min left)`;
      }
    }
    p.append(doc.createTextNode(
      `this pen is temporarily awake for billing renewal until ${until}. ` +
      'Shares, invites, devices, and access for other members are unavailable until the pen is renewed. ' +
      'Once payment completes, normal access restores automatically.'
    ));
    appendRenewButton();
    banner.replaceChildren(p, errP);
    banner.hidden = false;
    return;
  }

  strong.textContent = 'Renewal needed: ';
  p.append(strong);
  let until = 'soon';
  if (st.grace_until) {
    const d = new Date(st.grace_until);
    if (!Number.isNaN(d.getTime())) {
      const days = Math.max(0, Math.ceil((d.getTime() - now()) / 86400000));
      until = `${d.toISOString().slice(0, 10)} (${days} day${days === 1 ? '' : 's'} left)`;
    }
  }
  if (me && me.is_admin) {
    p.append(doc.createTextNode(
      `this pen is in its 30-day grace period and will go to sleep on ${until}. ` +
      'Any owner or admin can renew from this page for a fresh year (an admin who pays becomes an owner).'
    ));
    appendRenewButton();
  } else {
    p.append(doc.createTextNode(
      `this pen is in its 30-day grace period and will go to sleep on ${until}. ` +
      'Ask an owner or admin to renew it from this page.'
    ));
  }
  banner.replaceChildren(p, errP);
  banner.hidden = false;
}

export function renderPenDelete({ doc, api, navigate }, me) {
  const $ = id => doc.getElementById(id);
  const sec = $('pen-delete');
  if (!sec) return;
  const pd = me && me.pen_delete;
  if (!me || !me.is_owner || !pd || !pd.can_delete || !pd.pen) {
    sec.hidden = true;
    return;
  }

  const pen = String(pd.pen);
  $('pen-delete-name').textContent = pen;
  $('pen-delete-lead-name').textContent = pen;
  $('pen-delete-label').textContent = `Type ${pen} to confirm`;
  $('pen-delete-input').placeholder = pen;

  const ul = $('pen-delete-bullets');
  ul.replaceChildren();
  const addBullet = text => {
    const li = doc.createElement('li');
    li.textContent = text;
    ul.append(li);
  };
  const mCount = typeof pd.member_count === 'number' ? pd.member_count : 0;
  const dCount = typeof pd.device_count === 'number' ? pd.device_count : 0;
  addBullet(`Everyone in this pen (${mCount} member${mCount === 1 ? '' : 's'}, ${dCount} device${dCount === 1 ? '' : 's'}) loses access right away.`);
  if (Array.isArray(pd.other_owners) && pd.other_owners.length > 0) {
    const n = pd.other_owners.length;
    addBullet(`This also removes it for ${n} other owner${n === 1 ? '' : 's'} (${pd.other_owners.join(', ')}).`);
  }
  addBullet('Any active yearly subscription is cancelled immediately (remaining paid time is forfeited — no refund).');
  addBullet(`The name ${pen} is permanently retired and cannot be reused.`);
  addBullet('Encrypted backups are kept for 30 days and then deleted.');

  const openRow = $('pen-delete-open-row');
  const box = $('pen-delete-confirm-box');
  const inp = $('pen-delete-input');
  const go = $('pen-delete-go');
  const err = $('pen-delete-err');
  const syncMatch = () => {
    go.disabled = inp.value.trim().toLowerCase() !== pen.toLowerCase();
  };
  inp.oninput = syncMatch;
  $('pen-delete-open').onclick = () => {
    openRow.hidden = true;
    box.hidden = false;
    err.hidden = true;
    inp.value = '';
    syncMatch();
    if (typeof inp.focus === 'function') inp.focus();
  };
  $('pen-delete-cancel').onclick = () => {
    box.hidden = true;
    openRow.hidden = false;
    err.hidden = true;
    inp.value = '';
    syncMatch();
  };
  $('pen-delete-form').onsubmit = async ev => {
    ev.preventDefault();
    err.hidden = true;
    const val = inp.value.trim();
    if (val.toLowerCase() !== pen.toLowerCase()) {
      err.textContent = `Type ${pen} to confirm.`;
      err.hidden = false;
      return;
    }
    go.disabled = true;
    try {
      const r = await api('POST', '/pen/delete-token', { confirm: val });
      if (typeof r.url === 'string' && r.url.startsWith('https://')) {
        navigate(r.url);
        return;
      }
      throw new Error('Delete confirmation link was not returned.');
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
      syncMatch();
    }
  };
  sec.hidden = false;
}
