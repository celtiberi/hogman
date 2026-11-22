import {
  FAIL_CLOSED_FIREFOX,
  computeEffectiveRoutes,
  normalizeHost,
  resolveFirefoxProxy,
  sanitizeNativeSnapshot,
} from "./pac.js";

const NATIVE_HOST = "network.hogman.browser";
const REFRESH_TTL_MS = 10000;

let cachedSnapshot = null;
let cachedRoutes = {};
let lastFetchAt = 0;
let inFlightRefresh = null;

let state = {
  browser: "firefox",
  connected: false,
  nativeError: "",
  paused: false,
  conflict: "",
  conflictDetail: "",
  osProxyConflict: false,
  osProxyDetail: "",
  vpnOverride: false,
  vpnInterface: "",
  allowOSProxyOverride: false,
  lockProfile: false,
  entries: [],
  incognitoAllowed: false,
};

async function loadPrefs() {
  const stored = await browser.storage.local.get([
    "paused",
    "disabledZones",
    "enabledZones",
    "lockProfile",
    "approvedCustomZones",
  ]);
  return {
    paused: Boolean(stored.paused),
    disabledZones: stored.disabledZones || {},
    enabledZones: stored.enabledZones || {},
    lockProfile: Boolean(stored.lockProfile),
    approvedCustomZones: stored.approvedCustomZones || {},
  };
}

function updateBadge() {
  if (state.paused) {
    browser.action.setBadgeText({ text: "OFF" });
    browser.action.setBadgeBackgroundColor({ color: "#666666" });
    return;
  }
  if (state.nativeError) {
    browser.action.setBadgeText({ text: "!" });
    browser.action.setBadgeBackgroundColor({ color: "#b91c1c" });
    return;
  }
  const activeCount = state.entries.filter((e) => e.routeStatus === "active").length;
  browser.action.setBadgeText({ text: activeCount > 0 ? String(activeCount) : "" });
  browser.action.setBadgeBackgroundColor({ color: "#15803d" });
}

async function rebuildRoutesFromCache() {
  const prefs = await loadPrefs();
  state.paused = prefs.paused;
  state.lockProfile = prefs.lockProfile;
  if (typeof browser.extension?.isAllowedIncognitoAccess === "function") {
    try {
      state.incognitoAllowed = await browser.extension.isAllowedIncognitoAccess();
    } catch (_) {
      state.incognitoAllowed = false;
    }
  }
  if (!cachedSnapshot) {
    cachedRoutes = {};
    state.entries = [];
    updateBadge();
    return;
  }
  const snap = sanitizeNativeSnapshot(cachedSnapshot, prefs.approvedCustomZones);
  state.osProxyConflict = snap.osProxyConflict;
  state.osProxyDetail = snap.osProxyDetail;
  state.vpnOverride = snap.vpnOverride;
  state.vpnInterface = snap.vpnInterface;

  const { routes, entries } = computeEffectiveRoutes(snap.pens, prefs);
  cachedRoutes = routes;
  state.entries = entries;
  updateBadge();
}

// Singleflight refresh prevents spawning concurrent native host processes on
// browser startup / session restore.
function refreshSnapshot(force = false) {
  if (!force && cachedSnapshot && Date.now() - lastFetchAt < REFRESH_TTL_MS) {
    return rebuildRoutesFromCache();
  }
  if (inFlightRefresh) return inFlightRefresh;
  inFlightRefresh = (async () => {
    try {
      const resp = await browser.runtime.sendNativeMessage(NATIVE_HOST, { op: "list_pens" });
      if (resp && resp.ok) {
        cachedSnapshot = resp;
        lastFetchAt = Date.now();
        state.connected = true;
        state.nativeError = "";
        await browser.storage.local.set({ cachedSnapshot: resp });
      } else {
        state.connected = false;
        state.nativeError = (resp && resp.error) || "unexpected native host response";
      }
    } catch (err) {
      state.connected = false;
      state.nativeError = String(err && err.message ? err.message : err);
      if (!cachedSnapshot) {
        const stored = await browser.storage.local.get("cachedSnapshot");
        if (stored.cachedSnapshot) cachedSnapshot = stored.cachedSnapshot;
      }
    } finally {
      inFlightRefresh = null;
      await rebuildRoutesFromCache();
    }
  })();
  return inFlightRefresh;
}

async function handleProxyRequest(details) {
  const prefs = await loadPrefs();
  if (prefs.paused) {
    return undefined;
  }
  let host = "";
  try {
    host = normalizeHost(new URL(details.url).hostname);
  } catch (_) {
    return FAIL_CLOSED_FIREFOX;
  }

  if (!cachedSnapshot) {
    await refreshSnapshot(false);
  }
  let resolved = resolveFirefoxProxy(host, cachedRoutes);
  if (resolved === FAIL_CLOSED_FIREFOX && Date.now() - lastFetchAt > 1500) {
    // Unknown or newly joined pen: refresh once inside the request promise.
    await refreshSnapshot(true);
    resolved = resolveFirefoxProxy(host, cachedRoutes);
  }
  return resolved || FAIL_CLOSED_FIREFOX;
}

browser.proxy.onRequest.addListener(handleProxyRequest, {
  urls: ["*://*.pens.hogman.network/*"],
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && !changes.cachedSnapshot) {
    rebuildRoutesFromCache().catch(() => {});
  }
});

browser.runtime.onMessage.addListener((msg) => {
  if (!msg || typeof msg !== "object") return undefined;
  if (msg.type === "get_state") {
    return rebuildRoutesFromCache().then(() => ({ state }));
  }
  if (msg.type === "refresh") {
    return refreshSnapshot(true).then(() => ({ state }));
  }
  return undefined;
});

refreshSnapshot(true);
