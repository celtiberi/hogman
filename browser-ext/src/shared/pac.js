// Shared validation, per-profile allowlist, and fail-closed PAC builder.
// Loaded as an ES module by Chrome/Firefox background workers, popup, and tests.

import {
  FAIL_CLOSED_FIREFOX,
  FAIL_CLOSED_PROXY,
  HOGMAN_PORT_MAX,
  HOGMAN_PORT_MIN,
  HOSTED_ZONE_RE,
  ZONE_SUFFIX,
} from "./constants.js";

export {
  FAIL_CLOSED_FIREFOX,
  FAIL_CLOSED_PROXY,
  HOGMAN_PORT_MAX,
  HOGMAN_PORT_MIN,
  HOSTED_ZONE_RE,
  ZONE_SUFFIX,
};

export function normalizeHost(host) {
  if (typeof host !== "string") return "";
  return host.trim().toLowerCase().replace(/\.+$/, "");
}

export function isHostedZone(zone) {
  return typeof zone === "string" && HOSTED_ZONE_RE.test(zone);
}

export function isValidHogmanPort(port) {
  return Number.isInteger(port) && port >= HOGMAN_PORT_MIN && port <= HOGMAN_PORT_MAX;
}

// sanitizeNativeSnapshot strictly validates data returned by hogman-native-host.
// Only hosted *.pens.hogman.network zones with integer ports in 17000..26999
// are accepted; squatted or malformed entries are forced to port 0.
export function sanitizeNativeSnapshot(raw) {
  const pens = [];
  const seen = new Set();
  const list = Array.isArray(raw && raw.pens) ? raw.pens : [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const zone = normalizeHost(item.zone);
    if (!zone || seen.has(zone) || !isHostedZone(zone)) continue;
    const squatted = Boolean(item.squatted);
    const validPort = !squatted && isValidHogmanPort(item.port);
    seen.add(zone);
    pens.push({
      zone,
      port: validPort ? item.port : 0,
      up: Boolean(item.up) && validPort,
      hosted: true,
      squatted,
    });
  }
  pens.sort((a, b) => (b.zone.length - a.zone.length) || a.zone.localeCompare(b.zone));
  const rawProxyKind = typeof (raw && raw.os_proxy_kind) === "string" ? raw.os_proxy_kind : "";
  const rawVpnIface = typeof (raw && raw.vpn_interface) === "string" ? raw.vpn_interface : "";
  return {
    ok: Boolean(raw && raw.ok),
    version: typeof (raw && raw.version) === "string" ? raw.version : "",
    pens,
    osProxyConflict: Boolean(raw && raw.os_proxy_conflict),
    osProxyKind: rawProxyKind.length <= 64 ? rawProxyKind : "",
    vpnOverride: Boolean(raw && raw.vpn_override),
    vpnInterface: rawVpnIface.length <= 32 ? rawVpnIface : "",
  };
}

// computeEffectiveRoutes enforces D-19 per-profile allowlist-by-default:
// - Empty enabledZones means NOTHING routes in this browser profile until the
//   user explicitly enables a pen in this profile.
// - Disabled, squatted, or invalid-port pens always fail closed (never DIRECT).
export function computeEffectiveRoutes(pens, profilePrefs = {}) {
  const enabled = (profilePrefs && profilePrefs.enabledZones) || {};

  const routes = {}; // zone -> "PROXY 127.0.0.1:<port>" | FAIL_CLOSED_PROXY
  const entries = [];
  for (const pen of pens) {
    const allowedByProfile = Boolean(enabled[pen.zone]);
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
// appends "; DIRECT" to Hogman proxy rules. Even with routes === {} (no host,
// zero pens, paused, or all pens disabled), pens.hogman.network and all its
// subdomains fail closed while ordinary browsing stays DIRECT.
export function buildPACScript(routes = {}) {
  const safeInput = routes && typeof routes === "object" ? routes : {};
  const zones = Object.keys(safeInput).sort((a, b) => (b.length - a.length) || a.localeCompare(b));
  const table = {};
  for (const z of zones) {
    const val = safeInput[z];
    if (!isHostedZone(z)) continue;
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
    `  if (host === ${JSON.stringify(ZONE_SUFFIX)} || dnsDomainIs(host, ${JSON.stringify("." + ZONE_SUFFIX)})) return FAIL_CLOSED;`,
    '  return "DIRECT";',
    "}",
    "",
  ].join("\n");
}

// isKnownPenHost reports whether rawHost matches a zone already present in routes
// (whether active, offline, disabled in this profile, or squatted).
export function isKnownPenHost(rawHost, routes = {}) {
  const host = normalizeHost(rawHost);
  if (!host || !routes || typeof routes !== "object") return false;
  for (const z of Object.keys(routes)) {
    if (!isHostedZone(z)) continue;
    if (host === z || host.endsWith("." + z)) return true;
  }
  return false;
}

// resolveFirefoxProxy returns a Firefox proxy.ProxyInfo object for a request
// host matching pens.hogman.network or *.pens.hogman.network (always fail-closed
// for disabled, squatted, paused, or unknown pen hostnames).
export function resolveFirefoxProxy(rawHost, routes = {}) {
  const host = normalizeHost(rawHost);
  if (!host) return FAIL_CLOSED_FIREFOX;
  const safeRoutes = routes && typeof routes === "object" ? routes : {};
  const zones = Object.keys(safeRoutes).sort((a, b) => (b.length - a.length) || a.localeCompare(b));
  for (const z of zones) {
    if (!isHostedZone(z)) continue;
    if (host === z || host.endsWith("." + z)) {
      const target = safeRoutes[z];
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
  if (host === ZONE_SUFFIX || host.endsWith("." + ZONE_SUFFIX)) {
    return FAIL_CLOSED_FIREFOX;
  }
  return undefined;
}
