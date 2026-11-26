import assert from "node:assert/strict";
import test from "node:test";

import { STORAGE_KEYS } from "../src/shared/constants.js";
import { createPopupController } from "../src/shared/popup.js";

class FakeElement {
  constructor(tag, id = "") {
    this.tag = tag;
    this.id = id;
    this.type = "";
    this.dataset = {};
    this.disabled = false;
    this.checked = false;
    this.hidden = false;
    this.title = "";
    this.className = "";
    this.children = [];
    this.attrs = {};
    this._text = "";
    this.onclick = null;
    this.onchange = null;
  }

  get textContent() {
    return this._text;
  }

  set textContent(val) {
    this._text = String(val);
    if (this._text === "") {
      this.children = [];
    }
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  setAttribute(name, value) {
    this.attrs[name] = value;
  }
}

function collectMatching(el, pred, out = []) {
  if (pred(el)) out.push(el);
  for (const child of el.children) collectMatching(child, pred, out);
  return out;
}

function makeFakePopupDOM() {
  const byId = {};
  for (const id of [
    "banner",
    "perm-row",
    "perm-btn",
    "paused-row",
    "override-row",
    "override-text",
    "override-btn",
    "incognito-row",
    "pause",
    "refresh",
    "pen-list",
    "empty",
  ]) {
    byId[id] = new FakeElement("div", id);
  }
  const doc = {
    getElementById(id) {
      const el = byId[id];
      if (!el) throw new Error(`unexpected getElementById(${id})`);
      return el;
    },
    createElement(tag) {
      return new FakeElement(tag);
    },
    querySelectorAll(selector) {
      const out = [];
      if (selector.includes("#pen-list input[type=checkbox]")) {
        collectMatching(byId["pen-list"], (e) => e.tag === "input" && e.type === "checkbox", out);
      }
      for (const id of ["refresh", "pause", "override-btn"]) {
        if (selector.includes(`#${id}`)) out.push(byId[id]);
      }
      return out;
    },
  };
  return { doc, byId };
}

test("toggling a valid pen keeps squatted pen checkboxes disabled after re-render", async () => {
  const { doc, byId } = makeFakePopupDOM();
  const storage = { [STORAGE_KEYS.enabledZones]: {} };

  const api = {
    runtime: {
      async sendMessage() {
        const enabled = storage[STORAGE_KEYS.enabledZones] || {};
        return {
          state: {
            browser: "chrome",
            paused: false,
            nativeError: "",
            proxyError: "",
            conflict: "",
            conflictDetail: "",
            incognitoAllowed: true,
            missingHostPermission: false,
            entries: [
              {
                zone: "good.pens.hogman.network",
                port: 18000,
                allowedByProfile: Boolean(enabled["good.pens.hogman.network"]),
                squatted: false,
                routeStatus: enabled["good.pens.hogman.network"] ? "active" : "disabled",
              },
              {
                zone: "squat.pens.hogman.network",
                port: 0,
                allowedByProfile: false,
                squatted: true,
                routeStatus: "squatted",
              },
            ],
          },
        };
      },
    },
    storage: {
      local: {
        async get(keys) {
          const out = {};
          for (const k of keys) out[k] = storage[k];
          return out;
        },
        async set(obj) {
          Object.assign(storage, obj);
        },
      },
    },
  };

  const ctrl = createPopupController(doc, api);
  await ctrl.load();

  let boxes = doc.querySelectorAll("#pen-list input[type=checkbox]");
  assert.equal(boxes.length, 2);
  assert.equal(boxes[0].disabled, false);
  assert.equal(boxes[1].disabled, true);

  // Enable the valid pen: triggers storageSet + load() -> render() inside try,
  // followed by setControlsDisabled(false) in finally.
  boxes[0].checked = true;
  await boxes[0].onchange();

  boxes = doc.querySelectorAll("#pen-list input[type=checkbox]");
  assert.equal(storage[STORAGE_KEYS.enabledZones]["good.pens.hogman.network"], true);
  assert.equal(boxes[0].checked, true);
  assert.equal(boxes[0].disabled, false);
  assert.equal(boxes[1].disabled, true, "squatted checkbox must stay disabled after toggle re-render");
  assert.equal(byId.refresh.disabled, false);
  assert.equal(byId.pause.disabled, false);
});

test("IPC failure renders error banner instead of blank popup", async () => {
  const { doc, byId } = makeFakePopupDOM();
  const api = {
    runtime: {
      async sendMessage() {
        throw new Error("worker unavailable");
      },
    },
    storage: {
      local: {
        async get() { return {}; },
        async set() {},
      },
    },
  };

  const ctrl = createPopupController(doc, api);
  await ctrl.load();

  assert.equal(byId.banner.hidden, false);
  assert.match(byId.banner.textContent, /background worker/i);
  assert.equal(byId.empty.hidden, true);
});
