(() => {
  const $ = id => document.getElementById(id);
  const queryTheme = new URLSearchParams(location.search).get('theme') === 'work';
  let workApplied = false;

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

  const replaceLinks = (container, items, sep) => {
    if (!container) return;
    container.replaceChildren();
    items.forEach(([label, href], idx) => {
      if (sep && idx > 0) container.append(document.createTextNode(sep));
      const a = document.createElement('a');
      a.href = href;
      a.textContent = label;
      container.append(a);
    });
  };

  const applyWorkTheme = () => {
    if (workApplied) return;
    workApplied = true;
    document.documentElement.dataset.theme = 'work';
    document.title = 'Payment confirmed · Hogman for Work';
    setFavicon('/work-favicon.svg');

    $('brand-link').href = 'https://work.hogman.network/';
    $('brand-link').setAttribute('aria-label', 'Hogman for Work home');
    $('brand-icon').src = '/work-favicon.svg';
    $('brand-name').textContent = 'Hogman';
    $('brand-tag').hidden = false;

    replaceLinks($('nav-links'), [
      ['Overview', 'https://work.hogman.network/'],
      ['Docs', 'https://work.hogman.network/docs/'],
      ['GitHub', 'https://github.com/celtiberi/hogman'],
      ['Create a pen', '/'],
    ]);

    $('paid-title').textContent = 'Payment confirmed';
    $('paid-sub').textContent = 'Your one-time sign-up code unlocks a custom bare pen name with no random suffix.';
    $('ready-hint').textContent = 'This code works once. Keep it until your pen is created.';
    $('go').textContent = 'Create my pen';
    $('used').textContent = 'The sign-up code from this payment has already been used.';
    $('foot-note').textContent = 'Open source (AGPL-3.0), experimental, and not yet independently audited — evaluate carefully before relying on it for safety-critical systems.';
    replaceLinks($('foot-links'), [
      ['Overview', 'https://work.hogman.network/'],
      ['Docs', 'https://work.hogman.network/docs/'],
      ['Security', 'https://work.hogman.network/docs/security.html'],
      ['FAQ', 'https://work.hogman.network/docs/faq.html'],
      ['GitHub', 'https://github.com/celtiberi/hogman'],
    ], ' \u00b7 ');
  };

  if (queryTheme || /^get\.work\./i.test(location.hostname)) applyWorkTheme();
  fetch('/api/status', { cache: 'no-store' })
    .then(r => r.json())
    .then(s => { if (s && s.theme === 'work') applyWorkTheme(); })
    .catch(() => {});

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
      const suffix = queryTheme ? '?theme=work' : '';
      $('go').href = '/' + suffix + '#code=' + encodeURIComponent(s.code) + '&vanity=1';   // paid pens get a bare name
      $('copy-code').onclick = async () => {
        await navigator.clipboard.writeText(s.code);
        $('copy-code').textContent = 'Copied';
      };
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
