import { replaceLinks } from './dom.js';

export function applyWorkTheme(doc) {
  const $ = id => doc.getElementById(id);
  doc.documentElement.dataset.theme = 'work';
  doc.title = 'Portal · Hogman for Work';
  const meta = doc.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', '#14181f');

  $('brand-name').textContent = 'Hogman';
  $('brand-tag').hidden = false;

  $('nav-herd').textContent = 'Members';
  $('nav-host').textContent = 'Bridge';
  $('nav-docs').href = 'https://work.hogman.network/docs/';
  $('stat-sites-label').textContent = 'Bridges & apps';
  $('sites-title').textContent = 'Bridges & apps';
  $('all-devices-intro').textContent = 'Every enrolled staff workstation and bridge server across this pen. Remove a lost laptop or retired bridge at any time.';
  $('audit-intro').textContent = 'Audit log of member onboarding, offboarding, role changes, device enrollments, and bridged services in this pen.';
  $('status-pill-text').textContent = 'Connected to private network \u00b7 HTTPS only';

  $('sites-host-link').textContent = 'Bridge a device or app \u2193';
  $('sites-empty').replaceChildren(
    doc.createTextNode('No bridged devices or apps yet. Follow the '),
    Object.assign(doc.createElement('a'), {
      href: 'https://work.hogman.network/docs/share.html',
      target: '_blank',
      rel: 'noopener noreferrer',
      textContent: 'Bridging guide',
    }),
    doc.createTextNode(' to bridge an existing LAN controller or internal web app into this pen.')
  );

  $('device-card-hint').textContent = 'Generate a one-time link for another workstation (works once, expires in 1 hour). Use Get a share link for an always-on on-site bridge computer such as a Raspberry Pi or mini PC.';
  $('phone-line').hidden = true;
  $('invite-note').placeholder = 'Who is it for? (e.g. Jordan \u2014 HVAC contractor, Store North)';

  $('herd-title').textContent = 'Members';
  $('herd-intro').textContent = 'Everyone with access to this pen. Suspending cuts off all their devices in ~2 seconds and is reversible. Removing ends membership permanently and retires their handle and site names.';
  $('herd-recovery').textContent = 'Someone lost every enrolled device? There is no account recovery: issue a new invite, restore their role, then remove the old account (demote an old owner to admin first).';

  $('host-title').textContent = 'Bridge equipment or host an app';
  $('host-guide-link').textContent = 'Read the bridging guide \u2192';
  $('host-guide-link').href = 'https://work.hogman.network/docs/share.html';
  $('host-intro').textContent = 'Bridge an existing LAN controller (plain HTTP is fine on the LAN) or an internal web app into this pen over standard HTTPS (port 443). Read the bridging guide for step-by-step instructions on workstations, dedicated on-site bridge machines, and private site names.';
  $('host-hint-ctlog').replaceChildren(
    doc.createTextNode('Bridged site names appear in public certificate logs (traffic stays private) — see the guide for '),
    Object.assign(doc.createElement('code'), { textContent: '--private-name' }),
    doc.createTextNode('. A pen hides devices from the internet; it does not patch firmware.')
  );

  $('foot-tagline').textContent = 'Hogman for Work \u00b7 Open source (AGPL-3.0)';
  replaceLinks(doc, $('foot-links'), [
    ['work.hogman.network', 'https://work.hogman.network/'],
    ['Docs', 'https://work.hogman.network/docs/'],
    ['Bridging guide', 'https://work.hogman.network/docs/share.html'],
    ['Security', 'https://work.hogman.network/docs/security.html'],
    ['FAQ', 'https://work.hogman.network/docs/faq.html'],
  ], ' \u00b7 ');
}
