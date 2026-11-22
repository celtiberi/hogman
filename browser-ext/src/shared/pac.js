// Shared validation, per-profile allowlist, and fail-closed PAC builder.
// Loaded as an ES module by Chrome/Firefox background workers, popup, and tests.

export const HOSTED_ZONE_RE = /^[a-z][a-z0-9-]{1,28}[a-z0-9]\.pens\.hogman\.network$/;
export const GENERAL_ZONE_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
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

export function normalizeHost(host) {
  if (typeof host !== "string") return "";
  return host.trim().toLowerCase().replace(/\.+$/, "");
}

export function isHostedZone(zone) {
  return typeof zone === "string" && HOSTED_ZONE_RE.test(zone);
}

export function isValidGeneralZone(zone) {
  return typeof zone === "string" && zone.length <= 253 && GENERAL_ZONE_RE.test(zone);
}

export function isValidHogmanPort(port) {
  return Number.isInteger(port) && port >= HOGMAN_PORT_MIN && port <= HOGMAN_PORT_MAX;
}

// sanitizeNativeSnapshot strictly validates data returned by hogman-native-host.
// Only hosted zones (and explicitly approved custom zones) with integer ports in
// 17000..26999 are accepted; squatted or malformed entries are forced to port 0.
export function sanitizeNativeSnapshot(raw, approvedCustomZones = {}) {
  const pens = [];
  const seen = new Set();
  const list = Array.isArray(raw && raw.pens) ? raw.pens : [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const zone = normalizeHost(item.zone);
    if (!zone || seen.has(zone)) continue;
    const hosted = isHostedZone(zone);
    if (!hosted) {
      if (!isValidGeneralZone(zone) || !approvedCustomZones[zone]) continue;
    }
    const squatted = Boolean(item.squatted);
    const validPort = !squatted && isValidHogmanPort(item.port);
    seen.add(zone);
    pens.push({
      zone,
      port: validPort ? item.port : 0,
      up: Boolean(item.up) && validPort,
      hosted,
      squatted,
    });
  }
  pens.sort((a, b) => (b.zone.length - a.zone.length) || a.zone.localeCompare(b.zone));
  return {
    ok: Boolean(raw && raw.ok),
    version: typeof (raw && raw.version) === "string" ? raw.version : "",
    pens,
    osProxyConflict: Boolean(raw && raw.os_proxy_conflict),
    osProxyDetail: typeof (raw && raw.os_proxy_detail) === "string" ? raw.os_proxy_detail.slice(0, 200) : "",
    vpnOverride: Boolean(raw && raw.vpn_override),
    vpnInterface: typeof (raw && raw.vpn_interface) === "string" ? raw.vpn_interface.slice(0, 32) : "",
  };
}

// computeEffectiveRoutes merges sanitized pen entries with per-profile D-19
// isolation settings:
// - disabledZones[zone] === true -> fail closed (never DIRECT, never its proxy)
// - lockProfile === true -> any zone not in enabledZones fails closed
// - squatted or port === 0 -> fail closed
export function computeEffectiveRoutes(pens, profilePrefs = {}) {
  const disabled = profilePrefs.disabledZones || {};
  const enabled = profilePrefs.enabledZones || {};
  const lockProfile = Boolean(profilePrefs.lockProfile);

  const routes = {}; // zone -> "PROXY 127.0.0.1:<port>" | FAIL_CLOSED_PROXY
  const entries = [];
  for (const pen of pens) {
    const allowedByProfile = lockProfile ? Boolean(enabled[pen.zone]) : !disabled[pen.zone];
    let target = FAIL_CLOSED_PROXY;
    let routeStatus = "disabled";
    if (pen.squatted || !isValidHogmanPort(pen.port)) {
      target = FAIL_CLOSED_PROXY;
      routeStatus = pen.squatted ? "squatted" : "down";
    } else if (allowedByProfile) {
      target = `PROXY 127.0.0.1:${pen.port}`;
      routeStatus = pen.up ? "active" : "offline";
    }
    routes[pen.zone] = target;
    entries.push({ ...pen, allowedByProfile, routeStatus, target });
  }
  return { routes, entries };
}

// buildPACScript generates a pure-data, fail-closed PAC script in memory.
// Never interpolates raw strings as JS code, never uses dnsResolve(), and never
// appends "; DIRECT" to Hogman proxy rules.
export function buildPACScript(routes) {
  const zones = Object.keys(routes).sort((a, b) => (b.length - a.length) || a.localeCompare(b));
  const table = {};
  for (const z of zones) {
    const val = routes[z];
    if (!isValidGeneralZone(z)) continue;
    if (val === FAIL_CLOSED_PROXY || /^PROXY 127\.0\.0\.1:(?:1[7-9]\d{3}|2[0-6]\d{3})$/.test(val)) {
      table[z] = val;
    }
  }
  const ordered = Object.keys(table);
  return [
    "// Generated in memory by the Hogman browser extension.",
    `var ZONES = ${JSON.stringify(ordered)};`,
    `var ROUTES = ${JSON.stringify(table)};`,
    `var FAIL_CLOSED = ${JSON.stringify(FAIL_CLOSED_PROXY)};`,
    "function FindProxyForURL(url, host) {",
    '  host = String(host || "").toLowerCase().replace(/\\.+$/, "");',
    "  for (var i = 0; i < ZONES.length; i++) {",
    "    var z = ZONES[i];",
    '    if (host === z || dnsDomainIs(host, "." + z)) return ROUTES[z];',
    "  }",
    '  if (host === "pens.hogman.network" || dnsDomainIs(host, ".pens.hogman.network")) return FAIL_CLOSED;',
    '  return "DIRECT";',
    "}",
    "",
  ].join("\n");
}

// resolveFirefoxProxy returns a Firefox proxy.ProxyInfo object for a request
// host matching *.pens.hogman.network (always fail-closed for disabled,
// squatted, or unknown pen hostnames).
export function resolveFirefoxProxy(rawHost, routes) {
  const host = normalizeHost(rawHost);
  if (!host) return FAIL_CLOSED_FIREFOX;
  const zones = Object.keys(routes).sort((a, b) => (b.length - a.length) || a.localeCompare(b));
  for (const z of zones) {
    if (host === z || host.endsWith("." + z)) {
      const target = routes[z];
      const m = /^PROXY 127\.0\.0\.1:(\d+)$/.exec(target);
      if (m) {
        const port = Number(m[1]);
        if (isValidHogmanPort(port)) {
          return { type: "http", host: "127.0.0.1", port };
        }
      }
      return FAIL_CLOSED_FIREFOX;
    }
  }
  if (host === "pens.hogman.network" || host.endsWith(".pens.hogman.network")) {
    return FAIL_CLOSED_FIREFOX;
  }
  return undefined;
}
