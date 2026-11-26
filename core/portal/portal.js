import { createApiClient } from './js/api.js';
import { renderBillingBanner, renderPenDelete } from './js/billing.js';
import { createAdminDevicesSection, createDeviceLinkAdder, renderMyDevices } from './js/devices.js';
import { renderDirectory, renderOverview } from './js/directory.js';
import { createPressTwice, showErrorIn } from './js/dom.js';
import { createAuditSection, createHerdSection, createInvitesSection } from './js/members.js';
import { applyWorkTheme } from './js/theme.js';

export function initPortal({
  doc = document,
  fetchFn = fetch,
  clipboard = navigator.clipboard,
  navigate = url => { location.href = url; },
} = {}) {
  const $ = id => doc.getElementById(id);
  const api = createApiClient(fetchFn);
  const pressTwice = createPressTwice();

  let me = null;
  let isWork = false;
  let workApplied = false;
  let cachedSites = [];

  const refreshOverview = () => renderOverview(doc, {
    me,
    herd: herdSection.getState(),
    cachedSites,
    cachedAdminDevices: adminDevicesSection.getCached(),
  });

  const renderProfile = () => {
    if (me.network && me.network.theme === 'work') {
      isWork = true;
      if (!workApplied) {
        workApplied = true;
        applyWorkTheme(doc);
      }
    }
    $('hello').textContent = isWork ? `Signed in as ${me.member.handle}` : `You're in, ${me.member.handle}.`;
    $('whoami').textContent = `On ${me.zone} from ${me.this_device.name}. This page is only reachable from inside the network.`;
    doc.querySelectorAll('.zone').forEach(node => { node.textContent = me.zone; });
    renderMyDevices({
      doc,
      api,
      pressTwice,
      onAfterDelete: () => load(),
    }, me);
  };

  const loadDirectory = async () => {
    const sites = await api('GET', '/directory');
    cachedSites = Array.isArray(sites) ? sites : [];
    renderDirectory(doc, cachedSites);
    refreshOverview();
  };

  const refreshMeAndDelete = () => api('GET', '/me').then(fresh => {
    me = fresh;
    renderProfile();
    renderPenDelete({ doc, api, navigate }, me);
  });

  createDeviceLinkAdder({
    doc,
    api,
    clipboard,
    getIsWork: () => isWork,
  });

  const invitesSection = createInvitesSection({
    doc,
    api,
    pressTwice,
    clipboard,
    getMe: () => me,
  });

  const auditSection = createAuditSection({ doc, api });

  const adminDevicesSection = createAdminDevicesSection({
    doc,
    api,
    pressTwice,
    getMe: () => me,
    onLoaded: () => refreshOverview(),
    onAfterDelete: async () => {
      await Promise.allSettled([
        refreshMeAndDelete(),
        adminDevicesSection.load(),
        loadDirectory(),
        herdSection.load(false),
        auditSection.load(),
      ]);
    },
  });

  const herdSection = createHerdSection({
    doc,
    api,
    pressTwice,
    getMe: () => me,
    getIsWork: () => isWork,
    onOverviewChanged: refreshOverview,
    onAuditChanged: () => auditSection.load().catch(() => {}),
    onAfterKick: () => {
      refreshMeAndDelete().catch(() => {});
      loadDirectory().catch(() => {});
      if (me && me.can_invite) invitesSection.load().catch(() => {});
      adminDevicesSection.load().catch(() => {});
      auditSection.load().catch(() => {});
    },
  });

  async function load() {
    try {
      me = await api('GET', '/me');
      renderProfile();
      renderBillingBanner({ doc, api, navigate }, me, me.billing);
      renderPenDelete({ doc, api, navigate }, me);
    } catch (e) {
      $('whoami').textContent = 'Could not load your details: ' + e.message;
      return;
    }
    if (me.billing && me.billing.state === 'renew_only') {
      ['overview', 'sites', 'mine', 'invite', 'herd', 'all-devices', 'audit', 'host'].forEach(id => {
        const s = $(id);
        if (s) s.hidden = true;
      });
      return;
    }
    loadDirectory().catch(e => {
      $('sites').hidden = false;
      showErrorIn(doc, 'sites-err', e);
    });
    if (!me.devices) return; // a server
    if (me.can_invite) {
      $('invite').hidden = false;
      $('nav-invite').hidden = false;
      invitesSection.load().catch(e => showErrorIn(doc, 'invite-err', e));
    }
    if (me.is_admin) {
      $('herd').hidden = false;
      $('nav-herd').hidden = false;
      $('all-devices').hidden = false;
      $('nav-all-devices').hidden = false;
      $('audit').hidden = false;
      $('nav-audit').hidden = false;
      herdSection.updateSoloOwner();
      refreshOverview();
      herdSection.load(false).catch(e => showErrorIn(doc, 'herd-err', e));
      adminDevicesSection.load().catch(e => showErrorIn(doc, 'all-devices-err', e));
      auditSection.load().catch(e => showErrorIn(doc, 'audit-err', e));
    }
  }

  return { load };
}

if (typeof document !== 'undefined') {
  initPortal().load();
}
