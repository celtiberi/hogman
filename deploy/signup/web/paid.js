(() => {
  const $ = id => document.getElementById(id);
  const id = new URLSearchParams(location.search).get('session_id') || '';
  if (!/^cs_(test|live)_[A-Za-z0-9]{10,200}$/.test(id)) {
    $('waiting').hidden = true;
    $('bad').hidden = false;
    return;
  }
  let tries = 0;
  const poll = async () => {
    tries++;
    let s = {};
    try {
      const r = await fetch('/api/paid?session_id=' + encodeURIComponent(id), { cache: 'no-store' });
      s = await r.json();
    } catch (e) { /* try again */ }
    if (s.state === 'ready') {
      $('waiting').hidden = true;
      $('code').textContent = s.code;
      $('go').href = '/#code=' + encodeURIComponent(s.code);
      $('ready').hidden = false;
      return;
    }
    if (s.state === 'used') {
      $('waiting').hidden = true;
      $('used').hidden = false;
      return;
    }
    if (tries === 30) $('slow').hidden = false;   // about a minute
    if (tries > 90) return;                        // ~11 minutes: stop; a reload starts again
    setTimeout(poll, tries < 30 ? 2000 : 10000);
  };
  poll();
})();
