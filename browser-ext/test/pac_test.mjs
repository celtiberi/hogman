import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";

import {
  FAIL_CLOSED_FIREFOX,
  FAIL_CLOSED_PROXY,
  buildPACScript,
  computeEffectiveRoutes,
  normalizeHost,
  resolveFirefoxProxy,
  sanitizeNativeSnapshot,
} from "../src/shared/pac.js";

function evalPAC(pacScript, host) {
  const sandbox = {
    dnsDomainIs(h, suffix) {
      return h.length >= suffix.length && h.endsWith(suffix);
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(pacScript, sandbox, { timeout: 250 });
  return vm.runInContext(`FindProxyForURL(${JSON.stringify("https://" + host + "/")}, ${JSON.stringify(host)})`, sandbox, {
    timeout: 250,
  });
}

test("sanitizeNativeSnapshot validates hosted zones, ports, squatted entries, and custom opt-in", () => {
  const snap = sanitizeNativeSnapshot(
    {
      ok: true,
      version: "1",
      pens: [
        { zone: "farm2.pens.hogman.network", port: 25148, up: true, hosted: true },
        { zone: "squat2.pens.hogman.network", port: 25149, up: false, hosted: true, squatted: true },
        { zone: "badport.pens.hogman.network", port: 8080, up: true, hosted: true },
        { zone: "evil\";return \"DIRECT\";//.pens.hogman.network", port: 20000, up: true, hosted: true },
        { zone: "unapproved.example.org", port: 20001, up: true, hosted: false },
        { zone: "club.example.org", port: 20002, up: true, hosted: false },
      ],
      os_proxy_conflict: true,
      os_proxy_detail: "HTTP proxy",
      vpn_override: true,
      vpn_interface: "utun4",
    },
    { "club.example.org": true },
  );

  assert.equal(snap.ok, true);
  assert.equal(snap.osProxyConflict, true);
  assert.equal(snap.vpnOverride, true);
  assert.equal(snap.vpnInterface, "utun4");

  const byZone = Object.fromEntries(snap.pens.map((p) => [p.zone, p]));
  assert.deepEqual(Object.keys(byZone).sort(), [
    "badport.pens.hogman.network",
    "club.example.org",
    "farm2.pens.hogman.network",
    "squat2.pens.hogman.network",
  ]);
  assert.equal(byZone["farm2.pens.hogman.network"].port, 25148);
  assert.equal(byZone["farm2.pens.hogman.network"].up, true);
  assert.equal(byZone["squat2.pens.hogman.network"].port, 0);
  assert.equal(byZone["squat2.pens.hogman.network"].squatted, true);
  assert.equal(byZone["badport.pens.hogman.network"].port, 0);
  assert.equal(byZone["badport.pens.hogman.network"].up, false);
  assert.equal(byZone["club.example.org"].port, 20002);
});

test("generated PAC routes active pens, normalizes trailing dots, fails closed on disabled/squatted/unknown pens, and never uses dnsResolve or ; DIRECT", () => {
  const snap = sanitizeNativeSnapshot({
    ok: true,
    version: "1",
    pens: [
      { zone: "farm2.pens.hogman.network", port: 25148, up: true, hosted: true },
      { zone: "other.pens.hogman.network", port: 25149, up: true, hosted: true },
      { zone: "squat2.pens.hogman.network", port: 25150, up: false, hosted: true, squatted: true },
    ],
  });

  const { routes } = computeEffectiveRoutes(snap.pens, {
    disabledZones: { "other.pens.hogman.network": true },
  });
  const pac = buildPACScript(routes);

  assert.equal(pac.includes("dnsResolve"), false);
  assert.equal(pac.includes("; DIRECT"), false);
  assert.equal(pac.includes(":0"), false);

  assert.equal(evalPAC(pac, "home.farm2.pens.hogman.network"), "PROXY 127.0.0.1:25148");
  assert.equal(evalPAC(pac, "HOME.FARM2.PENS.HOGMAN.NETWORK."), "PROXY 127.0.0.1:25148");
  assert.equal(evalPAC(pac, "pigsty.farm2.pens.hogman.network..."), "PROXY 127.0.0.1:25148");

  // Disabled pen fails closed (never DIRECT, never its proxy) for D-19 profile isolation.
  assert.equal(evalPAC(pac, "home.other.pens.hogman.network"), FAIL_CLOSED_PROXY);
  // Squatted pen fails closed without touching the squatted port.
  assert.equal(evalPAC(pac, "home.squat2.pens.hogman.network"), FAIL_CLOSED_PROXY);
  // Unknown/unjoined pen fails closed rather than leaking DNS.
  assert.equal(evalPAC(pac, "home.unknown.pens.hogman.network"), FAIL_CLOSED_PROXY);

  // Normal public sites stay DIRECT (so OS VPN carries them).
  assert.equal(evalPAC(pac, "hogman.network"), "DIRECT");
  assert.equal(evalPAC(pac, "farm2.gate.hogman.network"), "DIRECT");
  assert.equal(evalPAC(pac, "example.com"), "DIRECT");
});

test("lockProfile allowlist fails closed on newly added pens until explicitly enabled", () => {
  const pens = sanitizeNativeSnapshot({
    ok: true,
    version: "1",
    pens: [
      { zone: "farm2.pens.hogman.network", port: 25148, up: true, hosted: true },
      { zone: "newuntrusted.pens.hogman.network", port: 25149, up: true, hosted: true },
    ],
  }).pens;

  const { routes } = computeEffectiveRoutes(pens, {
    lockProfile: true,
    enabledZones: { "farm2.pens.hogman.network": true },
  });
  assert.equal(routes["farm2.pens.hogman.network"], "PROXY 127.0.0.1:25148");
  assert.equal(routes["newuntrusted.pens.hogman.network"], FAIL_CLOSED_PROXY);
});

test("Firefox resolveFirefoxProxy normalizes trailing dots and fails closed cleanly", () => {
  const routes = {
    "farm2.pens.hogman.network": "PROXY 127.0.0.1:25148",
    "other.pens.hogman.network": FAIL_CLOSED_PROXY,
  };
  assert.deepEqual(resolveFirefoxProxy("pigsty.farm2.pens.hogman.network.", routes), {
    type: "http",
    host: "127.0.0.1",
    port: 25148,
  });
  assert.deepEqual(resolveFirefoxProxy("home.other.pens.hogman.network", routes), FAIL_CLOSED_FIREFOX);
  assert.deepEqual(resolveFirefoxProxy("home.unjoined.pens.hogman.network", routes), FAIL_CLOSED_FIREFOX);
  assert.equal(resolveFirefoxProxy("example.com", routes), undefined);
  assert.equal(normalizeHost("  FOO.BAR. "), "foo.bar");
});
