import {
  buildPACScript,
  computeEffectiveRoutes,
  sanitizeNativeSnapshot,
} from "./pac.js";

const NATIVE_HOST = "network.hogman.browser";

let nativePort = null;
let reconnectTimer = null;
let lastSnapshot = null;
let state = {
  browser: "chrome",
  connected: false,
  nativeError: "",
  paused: false,
  conflict: "", // "", "other_extension", "policy", "os_proxy"
  conflictDetail: "",
  osProxyConflict: false,
  osProxyDetail: "",
  vpnOverride: false,
  vpnInterface: "",
  allowOSProxyOverride: false,
  lockProfile: false,
  entries: [],
  incognitoAllowed: true,
};

async function loadPrefs() {
  const stored = await chrome.storage.local.get([
    "paused",
    "disabledZones",
    "enabledZones",
    "lockProfile",
    "allowOSProxyOverride",
    "approvedCustomZones",
  ]);
  return {
    paused: Boolean(stored.paused),
    disabledZones: stored.disabledZones || {},
    enabledZones: stored.enabledZones || {},
    lockProfile: Boolean(stored.lockProfile),
    allowOSProxyOverride: Boolean(stored.allowOSProxyOverride),
    approvedCustomZones: stored.approvedCustomZones || {},
  };
}

function updateBadge() {
  if (state.paused) {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#666666" });
    return;
  }
  if (state.conflict || state.nativeError) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#b91c1c" });
    return;
  }
  const activeCount = state.entries.filter((e) => e.routeStatus === "active").length;
  chrome.action.setBadgeText({ text: activeCount > 0 ? String(activeCount) : "" });
  chrome.action.setBadgeBackgroundColor({ color: "#15803d" });
}

async function applyProxyConfig() {
  const prefs = await loadPrefs();
  state.paused = prefs.paused;
  state.lockProfile = prefs.lockProfile;
  state.allowOSProxyOverride = prefs.allowOSProxyOverride;

  if (!lastSnapshot) {
    state.entries = [];
    updateBadge();
    return;
  }

  const snap = sanitizeNativeSnapshot(lastSnapshot, prefs.approvedCustomZones);
  state.osProxyConflict = snap.osProxyConflict;
  state.osProxyDetail = snap.osProxyDetail;
  state.vpnOverride = snap.vpnOverride;
  state.vpnInterface = snap.vpnInterface;

  const { routes, entries } = computeEffectiveRoutes(snap.pens, prefs);
  state.entries = entries;

  if (prefs.paused || entries.length === 0) {
    state.conflict = "";
    state.conflictDetail = "";
    await chrome.proxy.settings.clear({ scope: "regular" });
    updateBadge();
    return;
  }

  // Red-team C1: inspect levelOfControl before writing chrome.proxy.settings so
  // we never silently override another VPN/proxy extension or corporate policy.
  const current = await chrome.proxy.settings.get({});
  if (current.levelOfControl === "controlled_by_other_extensions") {
    state.conflict = "other_extension";
    state.conflictDetail = "Another browser extension controls proxy settings in this profile.";
    updateBadge();
    return;
  }
  if (current.levelOfControl === "not_controllable") {
    state.conflict = "policy";
    state.conflictDetail = "Browser proxy settings are locked by an organization policy.";
    updateBadge();
    return;
  }
  if (snap.osProxyConflict && !prefs.allowOSProxyOverride) {
    state.conflict = "os_proxy";
    state.conflictDetail = snap.osProxyDetail || "Non-Hogman OS proxy active";
    await chrome.proxy.settings.clear({ scope: "regular" });
    updateBadge();
    return;
  }

  state.conflict = "";
  state.conflictDetail = "";
  const pacData = buildPACScript(routes);
  await chrome.proxy.settings.set({
    value: {
      mode: "pac_script",
      pacScript: { data: pacData, mandatory: true },
    },
    scope: "regular",
  });
  updateBadge();
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectWatch();
  }, 5000);
}

function connectWatch() {
  if (nativePort) return;
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST);
    nativePort = port;
    state.connected = true;
    state.nativeError = "";

    port.onMessage.addListener((msg) => {
      if (msg && msg.ok) {
        lastSnapshot = msg;
        state.nativeError = "";
        applyProxyConfig().catch((err) => {
          state.nativeError = String(err && err.message ? err.message : err);
          updateBadge();
        });
      }
    });

    port.onDisconnect.addListener(() => {
      const errMsg = chrome.runtime.lastError ? chrome.runtime.lastError.message : "native host disconnected";
      nativePort = null;
      state.connected = false;
      state.nativeError = errMsg;
      updateBadge();
      scheduleReconnect();
    });

    port.postMessage({ op: "watch" });
  } catch (err) {
    nativePort = null;
    state.connected = false;
    state.nativeError = String(err && err.message ? err.message : err);
    updateBadge();
    scheduleReconnect();
  }
}

async function refreshNow() {
  if (nativePort) {
    try {
      nativePort.postMessage({ op: "list_pens" });
      return;
    } catch (_) {
      nativePort = null;
    }
  }
  connectWatch();
}

chrome.runtime.onInstalled.addListener(() => connectWatch());
chrome.runtime.onStartup.addListener(() => connectWatch());

chrome.proxy.onProxyError.addListener(() => {
  // Wakes a sleeping worker when an unmapped *.pens.hogman.network hits fail-closed.
  refreshNow();
});

chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "local") {
    applyProxyConfig().catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  if (msg.type === "get_state") {
    sendResponse({ state });
    return false;
  }
  if (msg.type === "refresh") {
    refreshNow().then(() => sendResponse({ state })).catch(() => sendResponse({ state }));
    return true;
  }
  return false;
});

connectWatch();
