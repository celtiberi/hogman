(() => {
  const $ = id => document.getElementById(id);
  const api = async (method, path, body) => {
    const r = await fetch('/api' + path, {
      method, cache: 'no-store',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(data.error || ('HTTP ' + r.status)), { status: r.status });
    return data;
  };

  // A link from the keeper fills the code in: https://.../#code=PIG-XXXX-XXXX
  // Vanity links may also carry &vanity=1 as a preview hint (the server enforces
  // whether the code is vanity or suffixed regardless of the URL hash).
  const m = location.hash.match(/code=([A-Za-z0-9-]+)/);
  if (m) $('code').value = m[1].toUpperCase();
  const vanityHint = /(?:^|[#&])vanity=1(?:&|$)/.test(location.hash);
  if (vanityHint && $('rand-suffix')) $('rand-suffix').hidden = true;

  // What pens' names end in (<pen>.pens.hogman.network), from the server.
  let sites = 'pens.hogman.network';
  const setSites = () => document.querySelectorAll('.sites').forEach(e => { e.textContent = sites; });

  // Optional pen UI theme ("work" when on the work signup host, confirmed by /api/status).
  let penTheme = /^get\.work\./i.test(location.hostname) ? 'work' : '';
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
    items.forEach(([label, href, current], idx) => {
      if (sep && idx > 0) container.append(document.createTextNode(sep));
      const a = document.createElement('a');
      a.href = href;
      a.textContent = label;
      if (current) a.setAttribute('aria-current', 'true');
      container.append(a);
    });
  };

  const applyWorkTheme = () => {
    if (workApplied) return;
    workApplied = true;
    document.documentElement.dataset.theme = 'work';
    document.title = 'Create a pen · Hogman for Work';
    setFavicon('/work-favicon.svg');

    $('brand-link').href = 'https://work.hogman.network/';
    $('brand-link').setAttribute('aria-label', 'Hogman for Work home');
    $('brand-icon').src = '/work-favicon.svg';
    $('brand-name').textContent = 'Hogman';
    $('brand-tag').hidden = false;

    replaceLinks($('nav-links'), [
      ['Overview', 'https://work.hogman.network/'],
      ['How it works', 'https://work.hogman.network/#how'],
      ['Security limits', 'https://work.hogman.network/#honest'],
      ['Docs', 'https://work.hogman.network/docs/'],
      ['Create a pen', '/', true],
    ]);

    $('hero-title').textContent = 'Create a pen';
    $('hero-sub').textContent = 'Private HTTPS network for your equipment controllers and internal web tools — standard browser certificates, zero public IP addresses, and ~2-second offboarding.';

    $('closed').textContent = 'Capacity is currently full. Join the waiting list and we\u2019ll email a sign-up code as room opens.';
    $('down').textContent = 'The sign-up service is temporarily unavailable. Please try again shortly.';

    $('code-hint-lead').textContent = 'Sign-ups are invite-only during the testbed. Opened a link? Your code is already filled in. Need access?';
    $('buy-copy').textContent = 'Need a custom bare pen name without waiting?';
    $('pen-label').textContent = 'Network name (pen)';
    $('pen').placeholder = 'store-north';
    $('handle-label').textContent = 'Your admin handle';
    $('handle').placeholder = 'alex-ops';
    $('handle-hint').textContent = 'You\u2019ll be the initial owner — able to invite staff, manage devices, and offboard accounts.';

    const disc = $('disclosure-text');
    disc.replaceChildren(
      Object.assign(document.createElement('strong'), { textContent: 'Before you choose a name: ' }),
      document.createTextNode('free sign-ups add a random 4-character suffix (such as '),
      Object.assign(document.createElement('code'), { textContent: 'store-north-7k2m' }),
      document.createTextNode(') so common names stay available; pen names are retired permanently once used. Pen and site hostnames appear in public Certificate Transparency logs (contents stay private), and hosted pens currently share '),
      Object.assign(document.createElement('code'), { textContent: sites }),
      document.createTextNode(' — use a separate browser profile for any pen you don\u2019t fully trust.')
    );

    $('go').textContent = 'Create pen';
    $('wait-title').textContent = 'Request early access';
    $('wait-intro').textContent = 'Leave your work email and we\u2019ll send a sign-up code as capacity opens.';
    $('w-pen-label').replaceChildren(
      document.createTextNode('Preferred pen name '),
      Object.assign(document.createElement('span'), { className: 'opt', textContent: '(optional)' })
    );
    $('w-pen').placeholder = 'store-north';
    $('w-note-label').replaceChildren(
      document.createTextNode('What are you protecting? '),
      Object.assign(document.createElement('span'), { className: 'opt', textContent: '(optional)' })
    );
    $('w-note').placeholder = 'e.g. refrigeration controllers, HVAC panels, internal tools';
    $('w-go').textContent = 'Request access';
    $('w-leave').textContent = 'Remove my email';

    $('working-title').textContent = 'Creating your pen';
    $('stage').textContent = 'Provisioning isolated network\u2026';

    $('done-title').textContent = 'Your pen is ready';
    $('done-intro-rest').textContent = 'is ready. Once your workstation joins, your management portal will be';
    $('done-step-3-rest').textContent = 'where you can add workstations, bridge on-site equipment, and manage members.';
    $('done-backup-warn').replaceChildren(
      Object.assign(document.createElement('strong'), { textContent: 'Appoint a backup owner right away: ' }),
      document.createTextNode('promote a second trusted person to Owner under '),
      Object.assign(document.createElement('em'), { textContent: 'Members' }),
      document.createTextNode('. There is no account recovery and no support backdoor — if the only owner loses every device, nobody can administer this pen again.')
    );

    $('foot-note').textContent = 'Invite-only testbed. Open source (AGPL-3.0), experimental, and not yet independently audited — evaluate carefully before relying on it for safety-critical systems.';
    replaceLinks($('foot-links'), [
      ['Overview', 'https://work.hogman.network/'],
      ['Docs', 'https://work.hogman.network/docs/'],
      ['Security', 'https://work.hogman.network/docs/security.html'],
      ['FAQ', 'https://work.hogman.network/docs/faq.html'],
      ['GitHub', 'https://github.com/celtiberi/hogman'],
    ], ' \u00b7 ');
  };

  if (penTheme === 'work') applyWorkTheme();

  // Optional Cloudflare Turnstile widget (loaded only when server advertises a site key).
  let tsSiteKey = '';
  let tsFormToken = '', tsWaitToken = '', tsRenewToken = '', tsWakeToken = '';
  let tsFormWidget = null, tsWaitWidget = null, tsRenewWidget = null, tsWakeWidget = null;
  const resetTurnstile = kind => {
    if (!window.turnstile) return;
    if (kind === 'form' && tsFormWidget !== null) { tsFormToken = ''; window.turnstile.reset(tsFormWidget); }
    if (kind === 'wait' && tsWaitWidget !== null) { tsWaitToken = ''; window.turnstile.reset(tsWaitWidget); }
    if (kind === 'renew' && tsRenewWidget !== null) { tsRenewToken = ''; window.turnstile.reset(tsRenewWidget); }
    if (kind === 'wake' && tsWakeWidget !== null) { tsWakeToken = ''; window.turnstile.reset(tsWakeWidget); }
  };
  const mountTurnstile = siteKey => {
    if (!siteKey || tsSiteKey) return;
    tsSiteKey = siteKey;
    const render = () => {
      if (!window.turnstile) return;
      const widgetTheme = penTheme === 'work' ? 'light' : 'dark';
      if ($('ts-form') && tsFormWidget === null) {
        $('ts-form').hidden = false;
        tsFormWidget = window.turnstile.render('#ts-form', {
          sitekey: tsSiteKey, theme: widgetTheme,
          callback: t => { tsFormToken = t; },
          'expired-callback': () => { tsFormToken = ''; },
          'error-callback': () => { tsFormToken = ''; },
        });
      }
      if ($('ts-wait') && tsWaitWidget === null) {
        $('ts-wait').hidden = false;
        tsWaitWidget = window.turnstile.render('#ts-wait', {
          sitekey: tsSiteKey, theme: widgetTheme,
          callback: t => { tsWaitToken = t; },
          'expired-callback': () => { tsWaitToken = ''; },
          'error-callback': () => { tsWaitToken = ''; },
        });
      }
      if ($('ts-renew') && tsRenewWidget === null) {
        $('ts-renew').hidden = false;
        tsRenewWidget = window.turnstile.render('#ts-renew', {
          sitekey: tsSiteKey, theme: widgetTheme,
          callback: t => { tsRenewToken = t; },
          'expired-callback': () => { tsRenewToken = ''; },
          'error-callback': () => { tsRenewToken = ''; },
        });
      }
      if ($('ts-wake') && tsWakeWidget === null) {
        $('ts-wake').hidden = false;
        tsWakeWidget = window.turnstile.render('#ts-wake', {
          sitekey: tsSiteKey, theme: widgetTheme,
          callback: t => { tsWakeToken = t; },
          'expired-callback': () => { tsWakeToken = ''; },
          'error-callback': () => { tsWakeToken = ''; },
        });
      }
    };
    const sc = document.createElement('script');
    sc.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    sc.async = true;
    sc.defer = true;
    sc.onload = render;
    document.head.appendChild(sc);
  };

  const penDisplay = raw => {
    const base = raw || '<network>';
    return vanityHint ? base : base + '-xxxx';
  };
  const setNames = () => {
    const p = penDisplay($('pen').value.trim().toLowerCase());
    document.querySelectorAll('.penname').forEach(e => { e.textContent = p; });
  };

  // Check syntax (and availability for vanity links) as you type, gently.
  let checkTimer = null, checkSeq = 0;
  $('pen').addEventListener('input', () => {
    setNames();
    clearTimeout(checkTimer);
    const pen = $('pen').value.trim().toLowerCase();
    const hint = $('pen-hint');
    if (!pen) { hint.className = 'hint'; hint.textContent = ''; hint.append(...defaultHint()); return; }
    checkTimer = setTimeout(async () => {
      const seq = ++checkSeq;
      try {
        const q = '/check?pen=' + encodeURIComponent(pen) + (vanityHint ? '&vanity=1' : '');
        const r = await api('GET', q);
        if (seq !== checkSeq) return;
        hint.className = r.free ? 'hint ok' : 'hint bad';
        if (r.free) {
          hint.textContent = r.vanity
            ? `✓ ${pen}.${sites} is free`
            : `✓ Your pen will be ${pen}-xxxx.${sites} (4 random characters added at setup)`;
        } else {
          hint.textContent = `✗ ${r.reason}`;
        }
      } catch (e) { if (seq === checkSeq) { hint.className = 'hint bad'; hint.textContent = e.message; } }
    }, 350);
  });
  const defaultHint = () => {
    const s = document.createElement('span'); s.className = 'penname'; s.textContent = penDisplay('');
    const lead = vanityHint
      ? 'For your private network itself. Sites and addresses will end in .'
      : 'We add a random 4-character ending so names stay available. Sites and addresses will end in .';
    return [document.createTextNode(lead), s, document.createTextNode('.' + sites)];
  };
  $('handle').addEventListener('input', setNames);
  for (const f of ['pen', 'handle']) $(f).addEventListener('change', setNames);   // autofill, paste, scripts

  let activeView = 'form';
  const show = id => { activeView = id; for (const s of ['form', 'wait', 'waited', 'renew', 'renewed', 'wake', 'working', 'done']) $(s).hidden = s !== id; };
  const cleanURL = () => location.pathname + location.search;

  // D-35 / I-7 Part 2: public sleeping-pen wake flow via /#wake=<pen>.
  const wakeMatch = location.hash.match(/(?:^|[#&])wake=([a-z][a-z0-9-]{1,28}[a-z0-9])/i);
  const wakePen = wakeMatch ? wakeMatch[1].toLowerCase() : '';
  if (wakePen) {
    history.replaceState(null, '', location.pathname);
    if ($('wake-pen')) $('wake-pen').textContent = wakePen;
  }
  if ($('wake-go')) {
    $('wake-go').addEventListener('click', async () => {
      $('wake-err').hidden = true;
      $('wake-done').hidden = true;
      if (!wakePen) {
        $('wake-err').textContent = 'Missing pen name in link.';
        $('wake-err').hidden = false;
        return;
      }
      if (tsSiteKey && !tsWakeToken) {
        $('wake-err').textContent = 'Please complete the verification check first.';
        $('wake-err').hidden = false;
        return;
      }
      $('wake-go').disabled = true;
      try {
        const body = { pen: wakePen };
        if (tsSiteKey) body.turnstile_token = tsWakeToken;
        const r = await api('POST', '/wake', body);
        $('wake-done').textContent = r.message || 'Wake request received. Open your pen\u2019s home page from a joined owner or admin device in 1\u20132 minutes to renew.';
        $('wake-done').hidden = false;
      } catch (e) {
        $('wake-err').textContent = e.message;
        $('wake-err').hidden = false;
        $('wake-go').disabled = false;
      } finally {
        resetTurnstile('wake');
      }
    });
  }

  // D-35: in-pen authenticated renewal flow via /#renew=<signed-token> and /?renewed=1.
  // The token lives only in the URL fragment and is stripped immediately from history.
  const urlParams = new URLSearchParams(location.search);
  const renewMatch = location.hash.match(/(?:^|[#&])renew=([A-Za-z0-9._-]+)/);
  let renewToken = renewMatch ? renewMatch[1] : '';
  if (renewToken) {
    history.replaceState(null, '', location.pathname);
  }
  const renewedParam = urlParams.get('renewed') === '1';
  if ($('renew-go')) {
    $('renew-go').addEventListener('click', async () => {
      $('renew-err').hidden = true;
      if (!renewToken) {
        $('renew-err').textContent = 'This renewal link has already been used. Open your pen\u2019s home page and click Renew now to start a fresh one.';
        $('renew-err').hidden = false;
        return;
      }
      if (tsSiteKey && !tsRenewToken) {
        $('renew-err').textContent = 'Please complete the verification check first.';
        $('renew-err').hidden = false;
        return;
      }
      $('renew-go').disabled = true;
      try {
        const body = { token: renewToken };
        if (tsSiteKey) body.turnstile_token = tsRenewToken;
        const r = await api('POST', '/renew', body);
        renewToken = '';
        location.href = r.url;
      } catch (e) {
        resetTurnstile('renew');
        $('renew-err').textContent = e.message;
        $('renew-err').hidden = false;
        $('renew-go').disabled = false;
      }
    });
  }

  // The waiting list: for when capacity is full, or there's no code.
  $('to-wait').addEventListener('click', ev => { ev.preventDefault(); show('wait'); $('w-email').focus(); });
  $('to-form').addEventListener('click', ev => { ev.preventDefault(); show('form'); });
  $('waited-back').addEventListener('click', ev => { ev.preventDefault(); history.replaceState(null, '', cleanURL()); show('wait'); });
  $('waited-code').addEventListener('click', ev => { ev.preventDefault(); history.replaceState(null, '', cleanURL()); show('form'); });
  $('w-leave').addEventListener('click', async () => {
    $('w-err').hidden = true;
    const email = $('w-email').value.trim();
    if (!email.includes('@')) { $('w-err').textContent = 'Type the email you joined with, then press this again.'; $('w-err').hidden = false; return; }
    if (tsSiteKey && !tsWaitToken) { $('w-err').textContent = 'Please complete the verification check first.'; $('w-err').hidden = false; return; }
    $('w-leave').disabled = true;
    try {
      const payload = { email };
      if (tsSiteKey) payload.turnstile_token = tsWaitToken;
      await api('POST', '/waitlist/leave', payload);
      $('waited-title').textContent = "You're off the list";
      $('waited-text').textContent = `If ${email} was on the waiting list, it isn't any more, and we've deleted it.`;
      show('waited');
    } catch (e) { $('w-err').textContent = e.message; $('w-err').hidden = false; }
    finally { resetTurnstile('wait'); $('w-leave').disabled = false; }
  });
  $('wait').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('w-err').hidden = true;
    const email = $('w-email').value.trim();
    if (!email.includes('@')) { $('w-err').textContent = 'Your email, please.'; $('w-err').hidden = false; return; }
    if (tsSiteKey && !tsWaitToken) { $('w-err').textContent = 'Please complete the verification check first.'; $('w-err').hidden = false; return; }
    $('w-go').disabled = true;
    try {
      const payload = { email, pen: $('w-pen').value.trim(), note: $('w-note').value.trim() };
      if (tsSiteKey) payload.turnstile_token = tsWaitToken;
      const r = await api('POST', '/waitlist', payload);
      $('waited-title').textContent = "You're on the list";
      $('waited-text').textContent = `You're number ${r.place}. We'll email ${email} a sign-up code when there's room (new requests may also receive a short confirmation email).`;
      show('waited');
    } catch (e) { $('w-err').textContent = e.message; $('w-err').hidden = false; }
    finally { resetTurnstile('wait'); $('w-go').disabled = false; }
  });

  // Raising a pen is a job on the server: start it, then check on it. The job's
  // id is kept for this tab, so a reload carries on instead of losing the link
  // (including while on the final setup-link screen during the 5-minute window).
  const JOB = 'hogman-signup-job';
  const JOB_DONE = 'hogman-signup-job-done';
  const defaultStages = [[0, 'Building the fence'], [8, 'Getting your HTTPS certificate'],
                         [20, 'Opening the gate'], [35, 'Raking the last of the straw'], [90, 'Taking longer than usual; hang on']];
  const workStages = [[0, 'Provisioning isolated network'], [8, 'Issuing HTTPS certificate'],
                      [20, 'Opening pen gate'], [35, 'Finalizing setup'], [90, 'Taking longer than usual; still working']];
  const showDone = r => {
    $('done-zone').textContent = r.zone;
    const homeURL = 'https://home.' + r.zone;
    $('done-home').textContent = homeURL;
    $('done-home-step').textContent = homeURL;
    $('link').textContent = r.join_link;
    if (r.join_qr_svg) { $('qr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(r.join_qr_svg); $('qr').closest('.qr').hidden = false; }
    else $('qr').closest('.qr').hidden = true;
    $('copy').onclick = async () => { await navigator.clipboard.writeText(r.join_link); $('copy').textContent = 'Copied'; };
    sessionStorage.setItem(JOB_DONE, '1');
    history.replaceState(null, '', cleanURL());   // the code is used up
    show('done');
  };
  const fail = msg => {
    sessionStorage.removeItem(JOB);
    sessionStorage.removeItem(JOB_DONE);
    show('form');
    $('err').textContent = msg; $('err').hidden = false;
    $('go').disabled = false;
    if ($('pen').value.trim()) $('pen').dispatchEvent(new Event('input'));
  };
  const follow = async id => {
    show('working');
    const t0 = Date.now();
    for (;;) {
      let j = null;
      try { j = await api('GET', '/job?id=' + encodeURIComponent(id)); }
      catch (e) {
        if (e.status === 404) {
          if (sessionStorage.getItem(JOB_DONE) === '1') {
            sessionStorage.removeItem(JOB);
            sessionStorage.removeItem(JOB_DONE);
            show('form');
            return;
          }
          return fail(e.message);
        }
      }   // otherwise a blip: keep checking
      if (j && j.state === 'done') return showDone(j.result);
      if (j && j.state === 'failed') return fail(j.error);
      const secs = j ? j.seconds : Math.round((Date.now() - t0) / 1000);
      const stages = penTheme === 'work' ? workStages : defaultStages;
      const stage = stages.filter(([at]) => secs >= at).pop()[1];
      $('stage').textContent = `${stage}… ${secs}s`;
      $('bar').style.width = Math.min(95, 5 + secs * 1.5) + '%';   // only ever moves forward
      await new Promise(r => setTimeout(r, 2000));
    }
  };

  $('form').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('err').hidden = true;
    setNames();
    const body = { code: $('code').value, pen: $('pen').value, handle: $('handle').value };
    if (penTheme) body.theme = penTheme;
    if (!body.code.trim() || !body.pen.trim() || !body.handle.trim()) {
      $('err').textContent = 'Fill in all three.'; $('err').hidden = false; return;
    }
    if (tsSiteKey && !tsFormToken) {
      $('err').textContent = 'Please complete the verification check first.'; $('err').hidden = false; return;
    }
    if (tsSiteKey) body.turnstile_token = tsFormToken;
    $('go').disabled = true;
    sessionStorage.removeItem(JOB_DONE);
    try {
      const r = await api('POST', '/create', body);
      sessionStorage.setItem(JOB, r.job);
      await follow(r.job);
    } catch (e) { resetTurnstile('form'); fail(e.message); }
  });
  const pending = sessionStorage.getItem(JOB);
  if (pending) {
    follow(pending);
  } else if (renewedParam) {
    show('renewed');
  } else if (renewToken) {
    show('renew');
  } else if (wakePen) {
    show('wake');
  } else if (location.hash === '#wait') {
    show('wait');   // a link straight to the waiting list
  }
  api('GET', '/status').then(s => {
    if (/^[a-z0-9.-]+$/.test(s.sites_domain || '')) { sites = s.sites_domain; setSites(); }
    if (s.theme === 'work') { penTheme = 'work'; applyWorkTheme(); }
    if (s.turnstile_site_key) mountTurnstile(s.turnstile_site_key);
    if (s.for_sale && s.open) {
      $('buy-line').hidden = false;
      $('buy').addEventListener('click', async () => {
        $('buy-err').hidden = true;
        if (tsSiteKey && !tsFormToken) {
          $('buy-err').textContent = 'Please complete the verification check below first.';
          $('buy-err').hidden = false;
          return;
        }
        $('buy').disabled = true;
        try {
          const body = tsSiteKey ? { turnstile_token: tsFormToken } : {};
          const r = await api('POST', '/checkout', body);
          location.href = r.url;   // Stripe's own page takes the card
        } catch (e) {
          resetTurnstile('form');
          $('buy-err').textContent = e.message;
          $('buy-err').hidden = false;
          $('buy').disabled = false;
        }
      });
    }
    if (!s.open) {
      $('closed').hidden = false;
      $('go').disabled = true;
      if (activeView !== 'working' && activeView !== 'done' && activeView !== 'renew' && activeView !== 'renewed' && activeView !== 'wake') show('wait');
    }
  }).catch(() => { $('down').hidden = false; });
  if (vanityHint) {
    $('pen-hint').textContent = '';
    $('pen-hint').append(...defaultHint());
  }
  setNames();
})();
