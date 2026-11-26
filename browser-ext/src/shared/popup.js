const api = typeof browser !== "undefined" ? browser : chrome;

const HOST_PERMISSION_ORIGINS = [
  "*://*.pens.hogman.network/*",
  "*://pens.hogman.network/*",
];

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

let currentState = null;

function render(st) {
  currentState = st;
  const banner = document.getElementById("banner");
  const permRow = document.getElementById("perm-row");
  const pausedRow = document.getElementById("paused-row");
  const overrideRow = document.getElementById("override-row");
  const overrideText = document.getElementById("override-text");
  const incognitoRow = document.getElementById("incognito-row");
  const pauseBtn = document.getElementById("pause");
  const list = document.getElementById("pen-list");
  const empty = document.getElementById("empty");

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
    const li = document.createElement("li");
    li.className = "pen-item";

    const main = document.createElement("div");
    main.className = "pen-main";

    const zoneEl = document.createElement("div");
    zoneEl.className = "pen-zone";
    zoneEl.textContent = e.zone;

    const meta = document.createElement("div");
    meta.className = "pen-meta";

    const pill = document.createElement("span");
    pill.className = `pill ${e.routeStatus}`;
    pill.textContent = e.routeStatus;
    meta.appendChild(pill);

    const detail = document.createElement("span");
    if (e.squatted) {
      detail.textContent = "blocked (unverified port listener)";
    } else if (!e.allowedByProfile) {
      detail.textContent = "blocked in this profile";
    } else if (e.port && e.legacy) {
      detail.textContent = `127.0.0.1:${e.port} · older agent (run hogman update)`;
    } else if (e.port) {
      detail.textContent = `127.0.0.1:${e.port}`;
    } else {
      detail.textContent = "unavailable";
    }
    meta.appendChild(detail);

    main.appendChild(zoneEl);
    main.appendChild(meta);

    const toggle = document.createElement("input");
    toggle.type = "checkbox";
    toggle.checked = Boolean(e.allowedByProfile);
    toggle.disabled = Boolean(e.squatted);
    toggle.title = `Allow ${e.zone} in this browser profile`;
    toggle.setAttribute("aria-label", `Allow ${e.zone} in this browser profile`);
    toggle.onchange = async () => {
      setControlsDisabled(true);
      try {
        const prefs = await storageGet(["enabledZones"]);
        const enabled = { ...(prefs.enabledZones || {}) };
        if (toggle.checked) enabled[e.zone] = true;
        else delete enabled[e.zone];
        await storageSet({ enabledZones: enabled });
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

function setControlsDisabled(disabled) {
  for (const el of document.querySelectorAll("#pen-list input[type=checkbox], #refresh, #pause, #override-btn")) {
    if (disabled) {
      el.dataset.prevDisabled = el.disabled ? "1" : "0";
      el.disabled = true;
    } else if (el.dataset.prevDisabled !== "1") {
      el.disabled = false;
    }
  }
}

function renderIPCError() {
  const banner = document.getElementById("banner");
  const empty = document.getElementById("empty");
  banner.textContent = "Could not communicate with the Hogman extension background worker. Click Refresh.";
  banner.hidden = false;
  empty.hidden = true;
}

async function load() {
  const resp = await sendMessage({ type: "get_state" });
  if (resp && resp.state) render(resp.state);
  else renderIPCError();
}

document.getElementById("refresh").onclick = async () => {
  const btn = document.getElementById("refresh");
  btn.disabled = true;
  try {
    const resp = await sendMessage({ type: "refresh" });
    if (resp && resp.state) render(resp.state);
    else renderIPCError();
  } finally {
    btn.disabled = false;
  }
};

document.getElementById("pause").onclick = async () => {
  if (!currentState) return;
  await storageSet({ paused: !currentState.paused });
  await load();
};

document.getElementById("override-btn").onclick = async () => {
  await storageSet({ allowOSProxyOverride: true });
  await load();
};

document.getElementById("perm-btn").onclick = async () => {
  if (api.permissions && typeof api.permissions.request === "function") {
    try {
      await api.permissions.request({ origins: HOST_PERMISSION_ORIGINS });
    } catch (_) {
      // ignore rejection; load() will reflect current permission state
    }
  }
  await load();
};

load();
