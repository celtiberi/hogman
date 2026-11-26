// Shared state model, badge computation, popup copy helpers, and async
// serialization for the Chrome and Firefox MV3 extensions.

import { BADGE_COLORS } from "./constants.js";

export function createInitialState(browser) {
  return {
    browser,
    connected: false,
    nativeError: "",
    proxyError: "",
    paused: false,
    conflict: "", // "", "other_extension", "policy", "os_proxy"
    conflictDetail: "",
    osProxyConflict: false,
    osProxyKind: "",
    allowOSProxyOverride: false,
    entries: [],
    incognitoAllowed: browser === "chrome",
    missingHostPermission: false,
  };
}

export function formatErrorMessage(err, fallback = "unknown error") {
  if (err && typeof err === "object" && typeof err.message === "string" && err.message) {
    return err.message;
  }
  const s = err == null ? "" : String(err);
  return s || fallback;
}

export function computeBadge(state) {
  if (state.paused) {
    return { text: "OFF", color: BADGE_COLORS.paused };
  }
  if (state.conflict || state.nativeError || state.proxyError || state.missingHostPermission) {
    return { text: "!", color: BADGE_COLORS.error };
  }
  const entries = Array.isArray(state.entries) ? state.entries : [];
  const activeCount = entries.filter((e) => e.routeStatus === "active").length;
  return {
    text: activeCount > 0 ? String(activeCount) : "",
    color: BADGE_COLORS.active,
  };
}

export function applyBadge(actionApi, state) {
  if (!actionApi) return;
  const { text, color } = computeBadge(state);
  Promise.resolve(actionApi.setBadgeText({ text })).catch(() => {});
  Promise.resolve(actionApi.setBadgeBackgroundColor({ color })).catch(() => {});
}

// createSerializedRunner wraps an async task so overlapping invocations coalesce
// into at most one trailing rerun after the current run completes.
export function createSerializedRunner(taskFn, onError) {
  let inFlight = null;
  let pending = false;

  return function run() {
    if (inFlight) {
      pending = true;
      return inFlight;
    }
    inFlight = Promise.resolve().then(async () => {
      try {
        do {
          pending = false;
          try {
            await taskFn();
          } catch (err) {
            if (onError) onError(err);
            else throw err;
          }
        } while (pending);
      } finally {
        pending = false;
        inFlight = null;
      }
    });
    return inFlight;
  };
}

export function describePenDetail(entry) {
  if (entry.squatted) {
    return "blocked (unverified port listener)";
  }
  if (!entry.allowedByProfile) {
    return "blocked in this profile";
  }
  if (entry.port) {
    return `127.0.0.1:${entry.port}`;
  }
  return "unavailable";
}
