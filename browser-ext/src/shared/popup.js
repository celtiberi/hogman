import { HOST_PERMISSION_ORIGINS, STORAGE_KEYS } from "./constants.js";
import { describePenDetail } from "./state.js";

// createPopupController isolates popup rendering, storage toggles, and IPC
// against injected DOM + WebExtension APIs so it can be unit-tested in Node
// without browser globals.
export function createPopupController(doc, api) {
  let currentState = null;

  async function sendMessage(msg) {
    try {
      return (await api.runtime.sendMessage(msg)) || {};
    } catch (_) {
      return {};
    }
  }

  async function storageGet(keys) {
    try {
      return (await api.storage.local.get(keys)) || {};
    } catch (_) {
      return {};
    }
  }

  async function storageSet(obj) {
    try {
      await api.storage.local.set(obj);
    } catch (_) {
      // ignore storage errors; load() will reflect current state
    }
  }

  function setControlsDisabled(disabled) {
    for (const el of doc.querySelectorAll("#pen-list input[type=checkbox], #refresh, #pause, #override-btn")) {
      if (disabled) {
        el.dataset.prevDisabled = el.disabled ? "1" : "0";
        el.disabled = true;
      } else if (el.dataset.prevDisabled === "0") {
        // Fresh checkboxes created by render() during an in-flight toggle have
        // prevDisabled === undefined; leave their rendered disabled state intact
        // so squatted pens are never re-enabled.
        el.disabled = false;
        delete el.dataset.prevDisabled;
      }
    }
  }

  function renderIPCError() {
    const banner = doc.getElementById("banner");
    const empty = doc.getElementById("empty");
    banner.textContent = "Could not communicate with the Hogman extension background worker. Click Refresh.";
    banner.hidden = false;
    empty.hidden = true;
  }

  function render(st) {
    currentState = st;
    const banner = doc.getElementById("banner");
    const permRow = doc.getElementById("perm-row");
    const pausedRow = doc.getElementById("paused-row");
    const overrideRow = doc.getElementById("override-row");
    const overrideText = doc.getElementById("override-text");
    const incognitoRow = doc.getElementById("incognito-row");
    const pauseBtn = doc.getElementById("pause");
    const list = doc.getElementById("pen-list");
    const empty = doc.getElementById("empty");

    pauseBtn.textContent = st.paused ? "Resume" : "Pause";

    banner.hidden = true;
    permRow.hidden = !(st.browser === "firefox" && st.missingHostPermission);
    pausedRow.hidden = !st.paused;
    overrideRow.hidden = true;
    incognitoRow.hidden = !(st.browser === "firefox" && !st.incognitoAllowed);

    if (st.nativeError) {
      banner.textContent = `Could not reach hogman-native-host (${st.nativeError}). Run "hogman browser-setup" in a terminal.`;
      banner.hidden = false;
    } else if (st.proxyError) {
      banner.textContent = `Could not update browser proxy settings (${st.proxyError}).`;
      banner.hidden = false;
    } else if (st.conflict === "other_extension" || st.conflict === "policy") {
      banner.textContent = st.conflictDetail;
      banner.hidden = false;
    } else if (st.conflict === "os_proxy") {
      overrideText.textContent = `A non-Hogman system proxy is active (${st.conflictDetail}). Hogman stepped aside so your OS proxy keeps working; pen names follow that OS proxy until you override it. Overriding bypasses your OS proxy for non-Hogman browsing in this browser profile.`;
      overrideRow.hidden = false;
    }

    list.textContent = "";
    const entries = Array.isArray(st.entries) ? st.entries : [];
    empty.hidden = entries.length > 0 || Boolean(st.nativeError || st.proxyError);

    for (const e of entries) {
      const li = doc.createElement("li");
      li.className = "pen-item";

      const main = doc.createElement("div");
      main.className = "pen-main";

      const zoneEl = doc.createElement("div");
      zoneEl.className = "pen-zone";
      zoneEl.textContent = e.zone;

      const meta = doc.createElement("div");
      meta.className = "pen-meta";

      const pill = doc.createElement("span");
      pill.className = `pill ${e.routeStatus}`;
      pill.textContent = e.routeStatus;
      meta.appendChild(pill);

      const detail = doc.createElement("span");
      detail.textContent = describePenDetail(e);
      meta.appendChild(detail);

      main.appendChild(zoneEl);
      main.appendChild(meta);

      const toggle = doc.createElement("input");
      toggle.type = "checkbox";
      toggle.checked = Boolean(e.allowedByProfile);
      toggle.disabled = Boolean(e.squatted);
      toggle.title = `Allow ${e.zone} in this browser profile`;
      toggle.setAttribute("aria-label", `Allow ${e.zone} in this browser profile`);
      toggle.onchange = async () => {
        setControlsDisabled(true);
        try {
          const prefs = await storageGet([STORAGE_KEYS.enabledZones]);
          const enabled = { ...(prefs[STORAGE_KEYS.enabledZones] || {}) };
          if (toggle.checked) enabled[e.zone] = true;
          else delete enabled[e.zone];
          await storageSet({ [STORAGE_KEYS.enabledZones]: enabled });
          await load();
        } finally {
          setControlsDisabled(false);
        }
      };

      li.appendChild(main);
      li.appendChild(toggle);
      list.appendChild(li);
    }
  }

  async function load() {
    const resp = await sendMessage({ type: "get_state" });
    if (resp && resp.state) render(resp.state);
    else renderIPCError();
  }

  doc.getElementById("refresh").onclick = async () => {
    const btn = doc.getElementById("refresh");
    btn.disabled = true;
    try {
      const resp = await sendMessage({ type: "refresh" });
      if (resp && resp.state) render(resp.state);
      else renderIPCError();
    } finally {
      btn.disabled = false;
    }
  };

  doc.getElementById("pause").onclick = async () => {
    if (!currentState) return;
    await storageSet({ [STORAGE_KEYS.paused]: !currentState.paused });
    await load();
  };

  doc.getElementById("override-btn").onclick = async () => {
    await storageSet({ [STORAGE_KEYS.allowOSProxyOverride]: true });
    await load();
  };

  doc.getElementById("perm-btn").onclick = async () => {
    if (api.permissions && typeof api.permissions.request === "function") {
      try {
        await api.permissions.request({ origins: [...HOST_PERMISSION_ORIGINS] });
      } catch (_) {
        // ignore rejection; load() will reflect current permission state
      }
    }
    await load();
  };

  return { load, render, setControlsDisabled };
}

if (typeof document !== "undefined") {
  const api = typeof browser !== "undefined" ? browser : chrome;
  createPopupController(document, api).load();
}
