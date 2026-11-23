import {
  buildPACScript,
  computeEffectiveRoutes,
  sanitizeNativeSnapshot,
} from "./pac.js";

const NATIVE_HOST = "network.hogman.browser";
const PROXY_ERROR_COOLDOWN_MS = 5000;

let nativePort = null;
let reconnectTimer = null;
let lastSnapshot = null;
let lastProxyErrorRefreshAt = 0;
let applyInFlight = null;
let applyPending = false;
let state = {
  browser: "chrome",
  connected: false,
  nativeError: "",
  paused: false,
  conflict: "", // "", "other_extension", "policy", "os_proxy"
  conflictDetail: "",
  osProxyConflict: false,
  osProxyKind: "",
  vpnOverride: false,
  vpnInterface: "",
  allowOSProxyOverride: false,
  entries: [],
  incognitoAllowed: true,
  missingHostPermission: false,
};

async function loadPrefs() {
  const stored = await chrome.storage.local.get([
    "paused",
    "enabledZones",
    "allowOSProxyOverride",
    "lastKnownOSProxyConflict",
    "lastKnownOSProxyKind",
  ]);
  return {
    paused: Boolean(stored.paused),
    enabledZones: stored.enabledZones || {},
    allowOSProxyOverride: Boolean(stored.allowOSProxyOverride),
    lastKnownOSProxyConflict: Boolean(stored.lastKnownOSProxyConflict),
    lastKnownOSProxyKind: typeof stored.lastKnownOSProxyKind === "string" ? stored.lastKnownOSProxyKind : "",
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

// Serialize proxy settings updates so concurrent startup, storage, and native
// host events cannot race and overwrite newer state with stale PAC data.
function applyProxyConfig() {
  if (applyInFlight) {
    applyPending = true;
    return applyInFlight;
  }
  applyInFlight = (async () => {
    try {
      do {
        applyPending = false;
        await applyProxyConfigOnce();
      } while (applyPending);
    } finally {
      applyInFlight = null;
    }
  })();
  return applyInFlight;
}

async function applyProxyConfigOnce() {
  const prefs = await loadPrefs();
  state.paused = prefs.paused;
  state.allowOSProxyOverride = prefs.allowOSProxyOverride;

  let snap = null;
  let routes = {};
  if (lastSnapshot) {
    snap = sanitizeNativeSnapshot(lastSnapshot);
    state.osProxyConflict = snap.osProxyConflict;
    state.osProxyKind = snap.osProxyKind;
    state.vpnOverride = snap.vpnOverride;
    state.vpnInterface = snap.vpnInterface;
    if (
      snap.osProxyConflict !== prefs.lastKnownOSProxyConflict ||
      snap.osProxyKind !== prefs.lastKnownOSProxyKind
    ) {
      await chrome.storage.local.set({
        lastKnownOSProxyConflict: snap.osProxyConflict,
        lastKnownOSProxyKind: snap.osProxyKind,
      });
    }

    const computed = computeEffectiveRoutes(snap.pens, prefs);
    state.entries = computed.entries;
    routes = prefs.paused ? {} : computed.routes;
  } else {
    state.osProxyConflict = prefs.lastKnownOSProxyConflict;
    state.osProxyKind = prefs.lastKnownOSProxyKind;
    state.vpnOverride = false;
    state.vpnInterface = "";
    state.entries = [];
    routes = {};
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
  const osProxyActive = snap ? snap.osProxyConflict : prefs.lastKnownOSProxyConflict;
  const osProxyKind = snap ? snap.osProxyKind : prefs.lastKnownOSProxyKind;
  if (osProxyActive && !prefs.allowOSProxyOverride) {
    state.conflict = "os_proxy";
    state.conflictDetail = osProxyKind || "non-Hogman OS proxy";
    // Step aside so a corporate OS proxy is not overridden with DIRECT.
    await chrome.proxy.settings.clear({ scope: "regular" });
    updateBadge();
    return;
  }

  // Always fail closed in every controllable state (including no host, zero pens,
  // paused, or all pens disabled in this profile): buildPACScript({}) routes
  // pens.hogman.network and *.pens.hogman.network to 127.0.0.1:1 while keeping
  // ordinary browsing DIRECT.
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
      lastSnapshot = null;
      state.connected = false;
      state.nativeError = errMsg;
      applyProxyConfig().catch(() => updateBadge());
      scheduleReconnect();
    });

    port.postMessage({ op: "watch" });
  } catch (err) {
    nativePort = null;
    lastSnapshot = null;
    state.connected = false;
    state.nativeError = String(err && err.message ? err.message : err);
    applyProxyConfig().catch(() => updateBadge());
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

chrome.runtime.onInstalled.addListener(() => {
  connectWatch();
});
chrome.runtime.onStartup.addListener(() => {
  connectWatch();
});

chrome.proxy.onProxyError.addListener(() => {
  // Wakes a sleeping worker when an unmapped *.pens.hogman.network hits fail-closed,
  // throttled so repeated subresource errors do not hammer the native host.
  const now = Date.now();
  if (now - lastProxyErrorRefreshAt < PROXY_ERROR_COOLDOWN_MS) return;
  lastProxyErrorRefreshAt = now;
  refreshNow();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.paused || changes.enabledZones || changes.allowOSProxyOverride)) {
    applyProxyConfig().catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  if (msg.type === "get_state") {
    applyProxyConfig()
      .then(() => sendResponse({ state }))
      .catch(() => sendResponse({ state }));
    return true;
  }
  if (msg.type === "refresh") {
    refreshNow()
      .then(() => applyProxyConfig())
      .then(() => sendResponse({ state }))
      .catch(() => sendResponse({ state }));
    return true;
  }
  return false;
});

connectWatch();
