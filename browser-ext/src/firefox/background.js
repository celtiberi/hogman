import {
  HOST_PERMISSION_ORIGINS,
  NATIVE_HOST,
  STORAGE_KEYS,
} from "./constants.js";
import {
  FAIL_CLOSED_FIREFOX,
  computeEffectiveRoutes,
  isKnownPenHost,
  normalizeHost,
  resolveFirefoxProxy,
  sanitizeNativeSnapshot,
} from "./pac.js";
import {
  applyBadge,
  createInitialState,
  createSerializedRunner,
  formatErrorMessage,
} from "./state.js";

const REFRESH_TTL_MS = 10000;
const NATIVE_ERROR_BACKOFF_MS = 5000;
const UNKNOWN_REFRESH_COOLDOWN_MS = 15000;

let cachedSnapshot = null;
let cachedRoutes = {};
let prefsLoaded = false;
let lastFetchAt = 0;
let lastFailedFetchAt = 0;
let lastUnknownRefreshAt = 0;
let inFlightRefresh = null;

const state = createInitialState("firefox");

async function loadPrefs() {
  const stored = await browser.storage.local.get([
    STORAGE_KEYS.paused,
    STORAGE_KEYS.enabledZones,
  ]);
  return {
    paused: Boolean(stored[STORAGE_KEYS.paused]),
    enabledZones: stored[STORAGE_KEYS.enabledZones] || {},
  };
}

async function checkHostPermission() {
  if (typeof browser.permissions?.contains !== "function") {
    return true;
  }
  try {
    return await browser.permissions.contains({ origins: [...HOST_PERMISSION_ORIGINS] });
  } catch (_) {
    return false;
  }
}

function updateBadge() {
  applyBadge(browser.action, state);
}

const rebuildRoutesFromCache = createSerializedRunner(rebuildRoutesFromCacheOnce, () => {
  cachedRoutes = {};
  prefsLoaded = false;
  state.entries = [];
  updateBadge();
});

async function rebuildRoutesFromCacheOnce() {
  const prefs = await loadPrefs();
  const missingHostPermission = !(await checkHostPermission());
  let incognitoAllowed = state.incognitoAllowed;
  if (typeof browser.extension?.isAllowedIncognitoAccess === "function") {
    try {
      incognitoAllowed = await browser.extension.isAllowedIncognitoAccess();
    } catch (_) {
      incognitoAllowed = false;
    }
  }
  state.paused = prefs.paused;
  state.missingHostPermission = missingHostPermission;
  state.incognitoAllowed = incognitoAllowed;
  if (!cachedSnapshot) {
    cachedRoutes = {};
    state.osProxyConflict = false;
    state.osProxyKind = "";
    state.entries = [];
    prefsLoaded = true;
    updateBadge();
    return;
  }
  const snap = sanitizeNativeSnapshot(cachedSnapshot);
  state.osProxyConflict = snap.osProxyConflict;
  state.osProxyKind = snap.osProxyKind;

  const { routes, entries } = computeEffectiveRoutes(snap.pens, prefs);
  cachedRoutes = prefs.paused ? {} : routes;
  state.entries = entries;
  prefsLoaded = true;
  updateBadge();
}

// Singleflight refresh prevents spawning concurrent native host processes on
// browser startup / session restore. Never fall back to persisted snapshots on
// native-host error: unverified loopback ports must fail closed.
function refreshSnapshot(force = false) {
  if (!force && cachedSnapshot && Date.now() - lastFetchAt < REFRESH_TTL_MS) {
    return prefsLoaded ? Promise.resolve() : rebuildRoutesFromCache();
  }
  if (!force && !cachedSnapshot && lastFailedFetchAt > 0 && Date.now() - lastFailedFetchAt < NATIVE_ERROR_BACKOFF_MS) {
    return prefsLoaded ? Promise.resolve() : rebuildRoutesFromCache();
  }
  if (inFlightRefresh) return inFlightRefresh;
  inFlightRefresh = (async () => {
    try {
      const resp = await browser.runtime.sendNativeMessage(NATIVE_HOST, { op: "list_pens" });
      if (resp && resp.ok) {
        cachedSnapshot = resp;
        lastFetchAt = Date.now();
        lastFailedFetchAt = 0;
        state.connected = true;
        state.nativeError = "";
      } else {
        cachedSnapshot = null;
        cachedRoutes = {};
        lastFetchAt = 0;
        lastFailedFetchAt = Date.now();
        state.connected = false;
        state.nativeError = (resp && resp.error) || "unexpected native host response";
      }
    } catch (err) {
      cachedSnapshot = null;
      cachedRoutes = {};
      lastFetchAt = 0;
      lastFailedFetchAt = Date.now();
      state.connected = false;
      state.nativeError = formatErrorMessage(err);
    } finally {
      try {
        await rebuildRoutesFromCache();
      } finally {
        inFlightRefresh = null;
      }
    }
  })();
  return inFlightRefresh;
}

async function handleProxyRequest(details) {
  try {
    if (!prefsLoaded) {
      await rebuildRoutesFromCache();
    }
    if (state.paused) {
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

    if (!cachedSnapshot || Date.now() - lastFetchAt >= REFRESH_TTL_MS) {
      await refreshSnapshot(false);
    }
    if (state.paused) return FAIL_CLOSED_FIREFOX;
    let resolved = resolveFirefoxProxy(host, cachedRoutes);
    // Only force-refresh for a genuinely unknown pen zone when connected (never
    // bypass NATIVE_ERROR_BACKOFF_MS when !cachedSnapshot, and never respawn the
    // native host for a pen already known disabled/squatted/down).
    if (
      cachedSnapshot &&
      resolved === FAIL_CLOSED_FIREFOX &&
      !isKnownPenHost(host, cachedRoutes) &&
      Date.now() - lastUnknownRefreshAt >= UNKNOWN_REFRESH_COOLDOWN_MS
    ) {
      lastUnknownRefreshAt = Date.now();
      await refreshSnapshot(true);
      if (state.paused) return FAIL_CLOSED_FIREFOX;
      resolved = resolveFirefoxProxy(host, cachedRoutes);
    }
    return resolved || FAIL_CLOSED_FIREFOX;
  } catch (_) {
    // Never reject from proxy.onRequest: Firefox treats a rejected promise as
    // DIRECT, which would fail open and leak pen hostnames to public DNS.
    return FAIL_CLOSED_FIREFOX;
  }
}

browser.proxy.onRequest.addListener(handleProxyRequest, {
  urls: [...HOST_PERMISSION_ORIGINS],
});

if (browser.permissions?.onAdded) {
  browser.permissions.onAdded.addListener(() => rebuildRoutesFromCache().catch(() => {}));
}
if (browser.permissions?.onRemoved) {
  browser.permissions.onRemoved.addListener(() => rebuildRoutesFromCache().catch(() => {}));
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes[STORAGE_KEYS.paused] || changes[STORAGE_KEYS.enabledZones])) {
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

// Clean up any snapshot persisted by pre-0.1.1 development installs.
browser.storage.local.remove("cachedSnapshot").catch(() => {});
refreshSnapshot(true).catch(() => {});
