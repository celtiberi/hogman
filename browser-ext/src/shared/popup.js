const api = typeof browser !== "undefined" ? browser : chrome;

const HOST_PERMISSION_ORIGINS = [
  "*://*.pens.hogman.network/*",
  "*://pens.hogman.network/*",
];

function sendMessage(msg) {
  return new Promise((resolve) => {
    const maybe = api.runtime.sendMessage(msg, (resp) => resolve(resp || {}));
    if (maybe && typeof maybe.then === "function") {
      maybe.then(resolve).catch(() => resolve({}));
    }
  });
}

function storageGet(keys) {
  return new Promise((resolve) => {
    const maybe = api.storage.local.get(keys, (res) => resolve(res || {}));
    if (maybe && typeof maybe.then === "function") {
      maybe.then(resolve).catch(() => resolve({}));
    }
  });
}

function storageSet(obj) {
  return new Promise((resolve) => {
    const maybe = api.storage.local.set(obj, () => resolve());
    if (maybe && typeof maybe.then === "function") {
      maybe.then(resolve).catch(() => resolve());
    }
  });
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
    banner.textContent = `Could not reach hogman-native-host (${st.nativeError}). Run "hogman-join browser-setup" in a terminal.`;
    banner.hidden = false;
  } else if (st.conflict === "other_extension" || st.conflict === "policy") {
    banner.textContent = st.conflictDetail;
    banner.hidden = false;
  } else if (st.conflict === "os_proxy") {
    overrideText.textContent = `A non-Hogman system proxy is active (${st.conflictDetail}). Hogman stepped aside so your OS proxy keeps working — pen sites are not routed or blocked by this extension. Overriding sends non-Hogman browsing DIRECT in this Chrome profile.`;
    overrideRow.hidden = false;
  }

  list.textContent = "";
  const entries = Array.isArray(st.entries) ? st.entries : [];
  empty.hidden = entries.length > 0;

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
      detail.textContent = `127.0.0.1:${e.port} · older agent (run hogman-join update)`;
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
    toggle.onchange = async () => {
      const prefs = await storageGet(["enabledZones"]);
      const enabled = { ...(prefs.enabledZones || {}) };
      if (toggle.checked) enabled[e.zone] = true;
      else delete enabled[e.zone];
      await storageSet({ enabledZones: enabled });
      await load();
    };

    li.appendChild(main);
    li.appendChild(toggle);
    list.appendChild(li);
  }
}

async function load() {
  const resp = await sendMessage({ type: "get_state" });
  if (resp && resp.state) render(resp.state);
}

document.getElementById("refresh").onclick = async () => {
  const resp = await sendMessage({ type: "refresh" });
  if (resp && resp.state) render(resp.state);
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
