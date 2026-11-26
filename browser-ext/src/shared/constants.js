// Shared constants for the Hogman browser extensions (Chrome & Firefox MV3).
// Imported as an ES module by background workers, popup UI, PAC builder, and tests.

export const NATIVE_HOST = "network.hogman.browser";

export const HOST_PERMISSION_ORIGINS = Object.freeze([
  "*://*.pens.hogman.network/*",
  "*://pens.hogman.network/*",
]);

export const HOSTED_ZONE_RE = /^[a-z][a-z0-9-]{1,28}[a-z0-9]\.pens\.hogman\.network$/;
export const HOGMAN_PORT_MIN = 17000;
export const HOGMAN_PORT_MAX = 26999;

// Port 1 on 127.0.0.1 is used for fail-closed routing (never port 0, which
// Chromium treats as invalid syntax and silently falls back to DIRECT).
export const FAIL_CLOSED_PROXY = "PROXY 127.0.0.1:1";
export const FAIL_CLOSED_FIREFOX = Object.freeze({
  type: "http",
  host: "127.0.0.1",
  port: 1,
});

export const BADGE_COLORS = Object.freeze({
  paused: "#666666",
  error: "#b91c1c",
  active: "#15803d",
});

export const STORAGE_KEYS = Object.freeze({
  paused: "paused",
  enabledZones: "enabledZones",
  allowOSProxyOverride: "allowOSProxyOverride",
  lastKnownOSProxyConflict: "lastKnownOSProxyConflict",
  lastKnownOSProxyKind: "lastKnownOSProxyKind",
});
