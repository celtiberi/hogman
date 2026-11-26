import { NATIVE_HOST, STORAGE_KEYS } from "./constants.js";
import {
  buildPACScript,
  computeEffectiveRoutes,
  sanitizeNativeSnapshot,
} from "./pac.js";
import {
  applyBadge,
  createInitialState,
  createSerializedRunner,
  formatErrorMessage,
} from "./state.js";

const PROXY_ERROR_COOLDOWN_MS = 5000;
const REFRESH_WAIT_TIMEOUT_MS = 2500;

let nativePort = null;
let reconnectTimer = null;
let lastSnapshot = null;
let lastProxyErrorRefreshAt = 0;
let nativeReplySeq = 0;
let pendingRefreshWaiters = [];
const state = createInitialState("chrome");

function settleRefreshWaiters(completedSeq) {
  if (pendingRefreshWaiters.length === 0) return;
  const remaining = [];
  for (const w of pendingRefreshWaiters) {
    if (w.wantSeq <= completedSeq) {
      w.resolve();
    } else {
      remaining.push(w);
    }
  }
  pendingRefreshWaiters = remaining;
}

function waitForNativeUpdate(timeoutMs = REFRESH_WAIT_TIMEOUT_MS) {
  const wantSeq = nativeReplySeq + 1;
  return new Promise((resolve) => {
    let settled = false;
    const entry = {
      wantSeq,
      resolve: () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const idx = pendingRefreshWaiters.indexOf(entry);
        if (idx !== -1) pendingRefreshWaiters.splice(idx, 1);
        resolve();
      },
    };
    const timer = setTimeout(entry.resolve, timeoutMs);
    pendingRefreshWaiters.push(entry);
  });
}

async function loadPrefs() {
  const stored = await chrome.storage.local.get([
    STORAGE_KEYS.paused,
    STORAGE_KEYS.enabledZones,
    STORAGE_KEYS.allowOSProxyOverride,
    STORAGE_KEYS.lastKnownOSProxyConflict,
    STORAGE_KEYS.lastKnownOSProxyKind,
  ]);
  return {
    paused: Boolean(stored[STORAGE_KEYS.paused]),
    enabledZones: stored[STORAGE_KEYS.enabledZones] || {},
    allowOSProxyOverride: Boolean(stored[STORAGE_KEYS.allowOSProxyOverride]),
    lastKnownOSProxyConflict: Boolean(stored[STORAGE_KEYS.lastKnownOSProxyConflict]),
    lastKnownOSProxyKind:
      typeof stored[STORAGE_KEYS.lastKnownOSProxyKind] === "string"
        ? stored[STORAGE_KEYS.lastKnownOSProxyKind]
        : "",
  };
}

function updateBadge() {
  applyBadge(chrome.action, state);
}

// Serialize proxy settings updates so concurrent startup, storage, and native
// host events cannot race and overwrite newer state with stale PAC data.
const applyProxyConfig = createSerializedRunner(applyProxyConfigOnce, (err) => {
  state.proxyError = formatErrorMessage(err);
  updateBadge();
});

async function applyProxyConfigOnce() {
  const prefs = await loadPrefs();
  state.paused = prefs.paused;
  state.allowOSProxyOverride = prefs.allowOSProxyOverride;

  let snap = null;
  let routes = {};
  let nextEntries = [];
  if (lastSnapshot) {
    snap = sanitizeNativeSnapshot(lastSnapshot);
    state.osProxyConflict = snap.osProxyConflict;
    state.osProxyKind = snap.osProxyKind;
    if (
      snap.osProxyConflict !== prefs.lastKnownOSProxyConflict ||
      snap.osProxyKind !== prefs.lastKnownOSProxyKind
    ) {
      await chrome.storage.local.set({
        [STORAGE_KEYS.lastKnownOSProxyConflict]: snap.osProxyConflict,
        [STORAGE_KEYS.lastKnownOSProxyKind]: snap.osProxyKind,
      });
    }

    const computed = computeEffectiveRoutes(snap.pens, prefs);
    nextEntries = computed.entries;
    routes = prefs.paused ? {} : computed.routes;
  } else {
    state.osProxyConflict = prefs.lastKnownOSProxyConflict;
    state.osProxyKind = prefs.lastKnownOSProxyKind;
    nextEntries = [];
    routes = {};
  }

  // Red-team C1: inspect levelOfControl before writing chrome.proxy.settings so
  // we never silently override another VPN/proxy extension or corporate policy.
  const current = await chrome.proxy.settings.get({});
  if (current.levelOfControl === "controlled_by_other_extensions") {
    state.entries = nextEntries;
    state.proxyError = "";
    state.conflict = "other_extension";
    state.conflictDetail = "Another browser extension controls proxy settings in this profile.";
    updateBadge();
    return;
  }
  if (current.levelOfControl === "not_controllable") {
    state.entries = nextEntries;
    state.proxyError = "";
    state.conflict = "policy";
    state.conflictDetail = "Browser proxy settings are locked by an organization policy.";
    updateBadge();
    return;
  }
  const osProxyActive = snap ? snap.osProxyConflict : prefs.lastKnownOSProxyConflict;
  const osProxyKind = snap ? snap.osProxyKind : prefs.lastKnownOSProxyKind;
  if (osProxyActive && !prefs.allowOSProxyOverride) {
    // Step aside so a corporate OS proxy is not overridden with DIRECT.
    await chrome.proxy.settings.clear({ scope: "regular" });
    state.entries = nextEntries;
    state.proxyError = "";
    state.conflict = "os_proxy";
    state.conflictDetail = osProxyKind || "non-Hogman OS proxy";
    updateBadge();
    return;
  }

  // Always fail closed in every controllable state (including no host, zero pens,
  // paused, or all pens disabled in this profile): buildPACScript({}) routes
  // pens.hogman.network and *.pens.hogman.network to 127.0.0.1:1 while keeping
  // ordinary browsing DIRECT.
  const pacData = buildPACScript(routes);
  await chrome.proxy.settings.set({
    value: {
      mode: "pac_script",
      pacScript: { data: pacData, mandatory: true },
    },
    scope: "regular",
  });
  state.entries = nextEntries;
  state.conflict = "";
  state.conflictDetail = "";
  state.proxyError = "";
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
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST);
    nativePort = port;
    state.connected = true;
    state.nativeError = "";

    port.onMessage.addListener((msg) => {
      if (nativePort !== port) return;
      const seq = ++nativeReplySeq;
      if (msg && msg.ok) {
        lastSnapshot = msg;
        state.nativeError = "";
        applyProxyConfig().finally(() => settleRefreshWaiters(seq));
      } else {
        state.nativeError = (msg && msg.error) ? String(msg.error) : "unexpected native host response";
        updateBadge();
        settleRefreshWaiters(seq);
      }
    });

    port.onDisconnect.addListener(() => {
      if (nativePort !== port) return;
      const seq = ++nativeReplySeq;
      const errMsg = chrome.runtime.lastError ? chrome.runtime.lastError.message : "native host disconnected";
      nativePort = null;
      lastSnapshot = null;
      state.connected = false;
      state.nativeError = errMsg;
      // If the native host was uninstalled/missing, clear any persisted OS proxy
      // conflict flag so Chrome does not stay stepped aside forever.
      const hostMissing = /not found|does not exist|not registered/i.test(errMsg);
      const prep = hostMissing
        ? chrome.storage.local.remove([
          STORAGE_KEYS.lastKnownOSProxyConflict,
          STORAGE_KEYS.lastKnownOSProxyKind,
        ]).catch(() => {})
        : Promise.resolve();
      prep
        .then(() => applyProxyConfig())
        .finally(() => settleRefreshWaiters(seq));
      scheduleReconnect();
    });

    port.postMessage({ op: "watch" });
  } catch (err) {
    const seq = ++nativeReplySeq;
    nativePort = null;
    lastSnapshot = null;
    state.connected = false;
    state.nativeError = formatErrorMessage(err);
    applyProxyConfig().finally(() => settleRefreshWaiters(seq));
    scheduleReconnect();
  }
}

async function refreshNow() {
  const wait = waitForNativeUpdate();
  if (nativePort) {
    try {
      nativePort.postMessage({ op: "list_pens" });
      await wait;
      return;
    } catch (_) {
      nativePort = null;
    }
  }
  connectWatch();
  await wait;
}

chrome.runtime.onInstalled.addListener(() => {
  applyProxyConfig().catch(() => {});
  connectWatch();
});
chrome.runtime.onStartup.addListener(() => {
  applyProxyConfig().catch(() => {});
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
  if (
    area === "local" &&
    (changes[STORAGE_KEYS.paused] ||
      changes[STORAGE_KEYS.enabledZones] ||
      changes[STORAGE_KEYS.allowOSProxyOverride])
  ) {
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

applyProxyConfig().catch(() => {});
connectWatch();
