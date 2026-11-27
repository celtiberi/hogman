import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";

import {
  FAIL_CLOSED_FIREFOX,
  FAIL_CLOSED_PROXY,
  buildPACScript,
  computeEffectiveRoutes,
  isKnownPenHost,
  isValidHogmanPort,
  resolveFirefoxProxy,
  sanitizeNativeSnapshot,
} from "../src/shared/pac.js";

function evalPAC(script) {
  const ctx = {
    dnsDomainIs(host, domain) {
      return host.endsWith(domain);
    },
  };
  vm.createContext(ctx);
  vm.runInContext(script, ctx);
  return ctx.FindProxyForURL;
}

test("sanitizeNativeSnapshot enforces hosted zones, integer port bounds, and squatted blocking", () => {
  const snap = sanitizeNativeSnapshot({
    ok: true,
    version: "1",
    os_proxy_conflict: true,
    os_proxy_kind: "http,pac",
    pens: [
      { zone: "farm2.pens.hogman.network.", port: 25148, up: true, hosted: true },
      { zone: "squat.pens.hogman.network", port: 25149, up: true, squatted: true },
      { zone: "lowport.pens.hogman.network", port: 16999, up: true },
      { zone: "highport.pens.hogman.network", port: 27000, up: true },
      { zone: "strport.pens.hogman.network", port: "20000", up: true },
      { zone: "floatport.pens.hogman.network", port: 20000.5, up: true },
      { zone: "custom.example.org", port: 18000, up: true },
      { zone: "evil.com;alert(1)", port: 18001, up: true },
    ],
  });

  assert.equal(snap.osProxyConflict, true);
  assert.equal(snap.osProxyKind, "http,pac");

  // Over-long metadata fields are rejected as empty instead of silently truncated.
  const overlong = sanitizeNativeSnapshot({
    ok: true,
    version: "1",
    os_proxy_kind: "k".repeat(65),
    vpn_interface: "v".repeat(33),
    pens: [],
  });
  assert.equal(overlong.osProxyKind, "");
  assert.equal(overlong.vpnInterface, "");

  const exact = sanitizeNativeSnapshot({
    ok: true,
    version: "1",
    os_proxy_kind: "k".repeat(64),
    vpn_interface: "v".repeat(32),
    pens: [],
  });
  assert.equal(exact.osProxyKind, "k".repeat(64));
  assert.equal(exact.vpnInterface, "v".repeat(32));

  const byZone = Object.fromEntries(snap.pens.map((p) => [p.zone, p]));
  assert.equal(Object.keys(byZone).length, 6);
  assert.equal(byZone["farm2.pens.hogman.network"].port, 25148);
  assert.equal(byZone["farm2.pens.hogman.network"].up, true);
  assert.equal(byZone["squat.pens.hogman.network"].port, 0);
  assert.equal(byZone["squat.pens.hogman.network"].up, false);
  assert.equal(byZone["lowport.pens.hogman.network"].port, 0);
  assert.equal(byZone["highport.pens.hogman.network"].port, 0);
  assert.equal(byZone["strport.pens.hogman.network"].port, 0);
  assert.equal(byZone["floatport.pens.hogman.network"].port, 0);
  assert.equal(byZone["custom.example.org"], undefined);
  assert.equal(byZone["evil.com;alert(1)"], undefined);

  assert.equal(isValidHogmanPort(17000), true);
  assert.equal(isValidHogmanPort(26999), true);
  assert.equal(isValidHogmanPort(16999), false);
  assert.equal(isValidHogmanPort(27000), false);
  assert.equal(isValidHogmanPort("20000"), false);
  assert.equal(isValidHogmanPort(0), false);
});

test("computeEffectiveRoutes is allowlist-by-default per profile (D-19)", () => {
  const pens = [
    { zone: "farm2.pens.hogman.network", port: 25148, up: true, squatted: false },
    { zone: "work.pens.hogman.network", port: 25149, up: true, squatted: false },
    { zone: "squat.pens.hogman.network", port: 0, up: false, squatted: true },
  ];

  // Empty prefs (fresh profile): every pen fails closed until explicitly enabled.
  const fresh = computeEffectiveRoutes(pens, {});
  assert.equal(fresh.routes["farm2.pens.hogman.network"], FAIL_CLOSED_PROXY);
  assert.equal(fresh.routes["work.pens.hogman.network"], FAIL_CLOSED_PROXY);
  assert.equal(fresh.routes["squat.pens.hogman.network"], FAIL_CLOSED_PROXY);

  // Enabling only farm2 routes farm2 and leaves work + squat fail-closed.
  const enabledOne = computeEffectiveRoutes(pens, {
    enabledZones: {
      "farm2.pens.hogman.network": true,
      "squat.pens.hogman.network": true, // squatted must still fail closed!
    },
  });
  assert.equal(enabledOne.routes["farm2.pens.hogman.network"], "PROXY 127.0.0.1:25148");
  assert.equal(enabledOne.routes["work.pens.hogman.network"], FAIL_CLOSED_PROXY);
  assert.equal(enabledOne.routes["squat.pens.hogman.network"], FAIL_CLOSED_PROXY);
});

test("buildPACScript is fail-closed for empty/paused/no-host, apex, trailing dots, and drops unsafe keys", () => {
  // Baseline PAC with empty routes (no host / zero pens / paused).
  const baselineScript = buildPACScript({});
  assert.ok(!baselineScript.includes("dnsResolve"), "PAC must never call dnsResolve");
  assert.ok(!baselineScript.includes("; DIRECT"), "PAC must never append ; DIRECT");
  const findBaseline = evalPAC(baselineScript);
  assert.equal(findBaseline("https://pens.hogman.network/", "pens.hogman.network"), FAIL_CLOSED_PROXY);
  assert.equal(findBaseline("https://pens.hogman.network./", "pens.hogman.network."), FAIL_CLOSED_PROXY);
  assert.equal(findBaseline("https://home.farm2.pens.hogman.network/", "home.farm2.pens.hogman.network"), FAIL_CLOSED_PROXY);
  assert.equal(findBaseline("https://example.com/", "example.com"), "DIRECT");

  // Mixed routes including unsafe keys and invalid targets that must be dropped.
  const script = buildPACScript({
    "farm2.pens.hogman.network": "PROXY 127.0.0.1:25148",
    "work.pens.hogman.network": FAIL_CLOSED_PROXY,
    "custom.example.org": "PROXY 127.0.0.1:25150",
    "badtarget.pens.hogman.network": "PROXY 127.0.0.1:25151; DIRECT",
    "badport.pens.hogman.network": "PROXY 127.0.0.1:16999",
    "evil\";return \"DIRECT": "PROXY 127.0.0.1:25152",
  });
  assert.ok(!script.includes("custom.example.org"), "non-hosted zone must be dropped");
  assert.ok(!script.includes("; DIRECT"), "unsafe ; DIRECT target must be dropped");
  assert.ok(!script.includes("16999"), "out-of-range port target must be dropped");
  assert.ok(!script.includes("evil"), "unsafe key must be dropped");

  const findProxy = evalPAC(script);
  assert.equal(findProxy("https://home.farm2.pens.hogman.network/", "home.farm2.pens.hogman.network"), "PROXY 127.0.0.1:25148");
  assert.equal(findProxy("https://home.farm2.pens.hogman.network./", "HOME.FARM2.PENS.HOGMAN.NETWORK."), "PROXY 127.0.0.1:25148");
  assert.equal(findProxy("https://home.work.pens.hogman.network/", "home.work.pens.hogman.network"), FAIL_CLOSED_PROXY);
  assert.equal(findProxy("https://home.badtarget.pens.hogman.network/", "home.badtarget.pens.hogman.network"), FAIL_CLOSED_PROXY);
  assert.equal(findProxy("https://home.unknown.pens.hogman.network/", "home.unknown.pens.hogman.network"), FAIL_CLOSED_PROXY);
  assert.equal(findProxy("https://pens.hogman.network/", "pens.hogman.network"), FAIL_CLOSED_PROXY);
  assert.equal(findProxy("https://custom.example.org/", "custom.example.org"), "DIRECT");
  assert.equal(findProxy("https://example.com/", "example.com"), "DIRECT");
});

test("resolveFirefoxProxy and isKnownPenHost handle active, disabled, apex, unknown, and trailing dots", () => {
  const routes = {
    "farm2.pens.hogman.network": "PROXY 127.0.0.1:25148",
    "work.pens.hogman.network": FAIL_CLOSED_PROXY,
    "custom.example.org": "PROXY 127.0.0.1:25150", // must be ignored (not hosted)
  };
  assert.deepEqual(
    resolveFirefoxProxy("photos.farm2.pens.hogman.network.", routes),
    { type: "http", host: "127.0.0.1", port: 25148 },
  );
  assert.deepEqual(resolveFirefoxProxy("home.work.pens.hogman.network", routes), FAIL_CLOSED_FIREFOX);
  assert.deepEqual(resolveFirefoxProxy("home.other.pens.hogman.network", routes), FAIL_CLOSED_FIREFOX);
  assert.deepEqual(resolveFirefoxProxy("pens.hogman.network", routes), FAIL_CLOSED_FIREFOX);
  assert.deepEqual(resolveFirefoxProxy("pens.hogman.network.", routes), FAIL_CLOSED_FIREFOX);
  assert.equal(resolveFirefoxProxy("custom.example.org", routes), undefined);
  assert.equal(resolveFirefoxProxy("example.com", routes), undefined);

  assert.equal(isKnownPenHost("home.work.pens.hogman.network", routes), true);
  assert.equal(isKnownPenHost("home.other.pens.hogman.network", routes), false);
  assert.equal(isKnownPenHost("custom.example.org", routes), false);
});
