import {
  FAIL_CLOSED_FIREFOX,
  computeEffectiveRoutes,
  isKnownPenHost,
  normalizeHost,
  resolveFirefoxProxy,
  sanitizeNativeSnapshot,
} from "./pac.js";

const NATIVE_HOST = "network.hogman.browser";
const REFRESH_TTL_MS = 10000;
const UNKNOWN_REFRESH_COOLDOWN_MS = 15000;
const HOST_PERMISSION_ORIGINS = [
  "*://*.pens.hogman.network/*",
  "*://pens.hogman.network/*",
];

let cachedSnapshot = null;
let cachedRoutes = {};
let lastFetchAt = 0;
let lastUnknownRefreshAt = 0;
let inFlightRefresh = null;

let state = {
  browser: "firefox",
  connected: false,
  nativeError: "",
  paused: false,
  conflict: "",
  conflictDetail: "",
  osProxyConflict: false,
  osProxyKind: "",
  vpnOverride: false,
  vpnInterface: "",
  allowOSProxyOverride: false,
  entries: [],
  incognitoAllowed: false,
  missingHostPermission: false,
};

async function loadPrefs() {
  const stored = await browser.storage.local.get([
    "paused",
    "enabledZones",
  ]);
  return {
    paused: Boolean(stored.paused),
    enabledZones: stored.enabledZones || {},
  };
}

async function checkHostPermission() {
  if (typeof browser.permissions?.contains !== "function") {
    return true;
  }
  try {
    return await browser.permissions.contains({ origins: HOST_PERMISSION_ORIGINS });
  } catch (_) {
    return false;
  }
}

function updateBadge() {
  if (state.paused) {
    browser.action.setBadgeText({ text: "OFF" });
    browser.action.setBadgeBackgroundColor({ color: "#666666" });
    return;
  }
  if (state.missingHostPermission || state.nativeError) {
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
  state.missingHostPermission = !(await checkHostPermission());
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
  const snap = sanitizeNativeSnapshot(cachedSnapshot);
  state.osProxyConflict = snap.osProxyConflict;
  state.osProxyKind = snap.osProxyKind;
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
    // Fail closed when paused: this listener fires only for pen URLs, so
    // non-pen browsing stays untouched while pen names never leak to public DNS.
    return FAIL_CLOSED_FIREFOX;
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
  // Only refresh for a genuinely unknown pen zone (never respawn the native
  // host on every request to a pen that is already known disabled/squatted/down).
  if (
    resolved === FAIL_CLOSED_FIREFOX &&
    !isKnownPenHost(host, cachedRoutes) &&
    Date.now() - lastUnknownRefreshAt >= UNKNOWN_REFRESH_COOLDOWN_MS
  ) {
    lastUnknownRefreshAt = Date.now();
    await refreshSnapshot(true);
    resolved = resolveFirefoxProxy(host, cachedRoutes);
  }
  return resolved || FAIL_CLOSED_FIREFOX;
}

browser.proxy.onRequest.addListener(handleProxyRequest, {
  urls: HOST_PERMISSION_ORIGINS,
});

if (browser.permissions?.onAdded) {
  browser.permissions.onAdded.addListener(() => rebuildRoutesFromCache().catch(() => {}));
}
if (browser.permissions?.onRemoved) {
  browser.permissions.onRemoved.addListener(() => rebuildRoutesFromCache().catch(() => {}));
}

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
