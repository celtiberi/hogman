import assert from "node:assert/strict";
import test from "node:test";

import { BADGE_COLORS, HOST_PERMISSION_ORIGINS, NATIVE_HOST, STORAGE_KEYS } from "../src/shared/constants.js";
import {
  applyBadge,
  computeBadge,
  createInitialState,
  createSerializedRunner,
  describePenDetail,
  formatErrorMessage,
} from "../src/shared/state.js";

test("shared constants and initial state defaults", () => {
  assert.equal(NATIVE_HOST, "network.hogman.browser");
  assert.deepEqual([...HOST_PERMISSION_ORIGINS], [
    "*://*.pens.hogman.network/*",
    "*://pens.hogman.network/*",
  ]);
  assert.equal(STORAGE_KEYS.enabledZones, "enabledZones");

  const chrome = createInitialState("chrome");
  assert.equal(chrome.browser, "chrome");
  assert.equal(chrome.incognitoAllowed, true);
  assert.equal(chrome.proxyError, "");
  assert.deepEqual(chrome.entries, []);

  const firefox = createInitialState("firefox");
  assert.equal(firefox.browser, "firefox");
  assert.equal(firefox.incognitoAllowed, false);
  assert.equal(firefox.proxyError, "");
});

test("computeBadge and applyBadge prioritize paused, then errors/conflicts, then active count", () => {
  assert.deepEqual(
    computeBadge({ paused: true, nativeError: "boom", entries: [{ routeStatus: "active" }] }),
    { text: "OFF", color: BADGE_COLORS.paused },
  );
  for (const field of ["conflict", "nativeError", "proxyError", "missingHostPermission"]) {
    const st = createInitialState("chrome");
    st[field] = field === "missingHostPermission" ? true : "problem";
    assert.deepEqual(computeBadge(st), { text: "!", color: BADGE_COLORS.error }, field);
  }
  assert.deepEqual(
    computeBadge({ entries: [{ routeStatus: "disabled" }, { routeStatus: "offline" }] }),
    { text: "", color: BADGE_COLORS.active },
  );
  assert.deepEqual(
    computeBadge({ entries: [{ routeStatus: "active" }, { routeStatus: "disabled" }, { routeStatus: "active" }] }),
    { text: "2", color: BADGE_COLORS.active },
  );

  const calls = [];
  const fakeAction = {
    setBadgeText(arg) { calls.push(["text", arg]); return Promise.reject(new Error("teardown")); },
    setBadgeBackgroundColor(arg) { calls.push(["color", arg]); return Promise.reject(new Error("teardown")); },
  };
  applyBadge(fakeAction, { entries: [{ routeStatus: "active" }] });
  assert.deepEqual(calls, [
    ["text", { text: "1" }],
    ["color", { color: BADGE_COLORS.active }],
  ]);
});

test("createSerializedRunner coalesces overlapping calls into one trailing rerun and recovers from errors", async () => {
  let active = 0;
  let maxActive = 0;
  let runs = 0;
  let releaseFirst;
  const firstEntered = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  let unblockFirst;
  const firstGate = new Promise((resolve) => {
    unblockFirst = resolve;
  });

  const errors = [];
  const run = createSerializedRunner(async () => {
    runs++;
    active++;
    maxActive = Math.max(maxActive, active);
    if (runs === 1) {
      releaseFirst();
      await firstGate;
    } else if (runs === 2) {
      active--;
      throw new Error("transient failure");
    }
    active--;
  }, (err) => {
    errors.push(formatErrorMessage(err));
  });

  const p1 = run();
  await firstEntered;
  // Three overlapping triggers while run 1 is in flight coalesce into one rerun (run 2).
  const p2 = run();
  const p3 = run();
  const p4 = run();
  assert.equal(p1, p2);
  assert.equal(p2, p3);
  assert.equal(p3, p4);
  unblockFirst();
  await p1;
  assert.equal(maxActive, 1);
  assert.equal(runs, 2);
  assert.deepEqual(errors, ["transient failure"]);

  // Runner remains healthy for subsequent calls.
  await run();
  assert.equal(runs, 3);

  // Without onError, errors reject AND reset pending/inFlight cleanly.
  let failOnce = true;
  let throwingRuns = 0;
  const throwingRunner = createSerializedRunner(async () => {
    throwingRuns++;
    if (failOnce) {
      failOnce = false;
      throw new Error("boom");
    }
  });
  await assert.rejects(() => throwingRunner(), /boom/);
  await throwingRunner();
  assert.equal(throwingRuns, 2);

  // Synchronous throw from a non-async taskFn must not wedge inFlight.
  let syncCalls = 0;
  const syncErrors = [];
  const syncRunner = createSerializedRunner(() => {
    syncCalls++;
    if (syncCalls === 1) throw new Error("sync boom");
    return Promise.resolve();
  }, (err) => {
    syncErrors.push(formatErrorMessage(err));
  });
  await syncRunner();
  await syncRunner();
  assert.equal(syncCalls, 2);
  assert.deepEqual(syncErrors, ["sync boom"]);
});

test("describePenDetail and formatErrorMessage cover all states", () => {
  assert.equal(describePenDetail({ squatted: true, port: 0, allowedByProfile: true }), "blocked (unverified port listener)");
  assert.equal(describePenDetail({ squatted: false, port: 18000, allowedByProfile: false }), "blocked in this profile");
  assert.equal(describePenDetail({ squatted: false, port: 18000, allowedByProfile: true }), "127.0.0.1:18000");
  assert.equal(describePenDetail({ squatted: false, port: 0, allowedByProfile: true }), "unavailable");

  assert.equal(formatErrorMessage(new Error("oops")), "oops");
  assert.equal(formatErrorMessage("raw string"), "raw string");
  assert.equal(formatErrorMessage(null, "fallback"), "fallback");
  assert.equal(formatErrorMessage("", "fallback"), "fallback");
});
