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
        const rm = document.createElement('button'); rm.className = 'link'; rm.type = 'button'; rm.textContent = 'Remove';
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
      $('qr').hidden = !r.join_qr_svg;
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
        $('expires').textContent = `${kind === 'server' ? 'Server link. ' : ''}Works once, expires in ${Math.ceil(left / 60)} min.`;
      };
      $('qr').classList.remove('expired');
      tick();
      timer = setInterval(tick, 15000);
    } catch (e) { showError(e); }
    finally { $('add-personal').disabled = $('add-server').disabled = false; }
  };
  $('add-personal').onclick = () => add('personal');
  $('add-server').onclick = () => add('server');

  const load = async () => {
    try { me = await api('GET', '/me'); render(); }
    catch (e) { $('whoami').textContent = 'Could not load your details: ' + e.message; }
  };
  load();
})();
