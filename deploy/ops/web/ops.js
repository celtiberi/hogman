(function () {
  "use strict";

  const POLL_MS = 60000;
  const STALE_SEC = 120;

  let latestData = null;

  const $ = (id) => document.getElementById(id);

  function fmtBytes(n) {
    if (!Number.isFinite(n) || n < 0) return "—";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let val = n;
    let idx = 0;
    while (val >= 1024 && idx < units.length - 1) {
      val /= 1024;
      idx++;
    }
    return (idx === 0 ? Math.round(val) : val.toFixed(1)) + " " + units[idx];
  }

  function fmtDuration(sec) {
    if (!Number.isFinite(sec) || sec <= 0) return "0m";
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    return Math.max(1, m) + "m";
  }

  function setBar(el, used, total) {
    if (!el) return;
    const pct = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
    el.style.width = pct + "%";
    el.className = "bar-fill" + (pct >= 90 ? " bad" : pct >= 75 ? " warn" : "");
  }

  function showBanner(msg, isError) {
    const b = $("banner");
    if (!msg) {
      b.textContent = "";
      b.className = "banner hidden";
      return;
    }
    b.textContent = msg;
    b.className = "banner" + (isError ? " error" : "");
  }

  function statePillClass(state) {
    if (state === "running" || state === "active") return "pill pill-ok";
    if (state === "sleeping" || state === "renew_only") return "pill pill-warn";
    if (state === "down" || state === "failed" || state === "inactive") return "pill pill-bad";
    return "pill pill-muted";
  }

  function renderPens(pens) {
    const tbody = $("pens-tbody");
    tbody.replaceChildren();
    const q = ($("pen-search").value || "").trim().toLowerCase();
    const filter = $("pen-state-filter").value;

    const filtered = (pens || []).filter((p) => {
      if (q && !(p.name || "").toLowerCase().includes(q)) return false;
      if (filter === "all") return true;
      if (filter === "other") {
        return p.state !== "running" && p.state !== "sleeping" && p.state !== "renew_only";
      }
      return p.state === filter;
    });

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "muted";
      td.textContent = pens && pens.length > 0 ? "No pens match this filter." : "No pens on this host.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const p of filtered) {
      const tr = document.createElement("tr");

      const tdName = document.createElement("td");
      tdName.className = "mono";
      tdName.textContent = p.name || "";
      tr.appendChild(tdName);

      const tdPlan = document.createElement("td");
      const plan = p.plan || "personal";
      const theme = p.theme || "default";
      tdPlan.textContent = plan + " / " + theme;
      tr.appendChild(tdPlan);

      const tdState = document.createElement("td");
      const pill = document.createElement("span");
      pill.className = statePillClass(p.state);
      pill.textContent = p.state || "unknown";
      tdState.appendChild(pill);
      tr.appendChild(tdState);

      const tdCont = document.createElement("td");
      tdCont.className = "mono";
      tdCont.textContent = (p.containers_up || 0) + " / " + (p.containers_total || 0);
      tr.appendChild(tdCont);

      const tdRam = document.createElement("td");
      tdRam.className = "mono";
      tdRam.textContent = p.ram_bytes ? fmtBytes(p.ram_bytes) : "—";
      tr.appendChild(tdRam);

      const tdBill = document.createElement("td");
      tdBill.className = "muted mono";
      if (p.delete_after) {
        tdBill.textContent = "delete " + p.delete_after.slice(0, 10);
      } else if (p.paid_until) {
        tdBill.textContent = "paid until " + p.paid_until.slice(0, 10);
      } else {
        tdBill.textContent = "house / unbilled";
      }
      tr.appendChild(tdBill);

      tbody.appendChild(tr);
    }
  }

  function render(data) {
    latestData = data;
    const host = data.host || {};
    const cap = host.capacity || {};
    const wl = data.waitlist || {};

    $("host-meta").textContent =
      (host.name || "host") +
      " · " +
      (host.version || "unknown") +
      " · up " +
      fmtDuration(host.uptime_sec || 0);

    $("viewer-badge").textContent = data.viewer ? "viewer: " + data.viewer : "";

    let ageSec = null;
    if (data.generated_at) {
      const parsed = Date.parse(data.generated_at);
      if (!Number.isNaN(parsed)) {
        ageSec = Math.max(0, Math.floor((Date.now() - parsed) / 1000));
      }
    }
    const fresh = $("freshness-badge");
    if (ageSec === null) {
      fresh.className = "pill pill-warn";
      fresh.textContent = "snapshot time unknown";
      showBanner("Snapshot timestamp missing or invalid.", false);
    } else if (ageSec > STALE_SEC) {
      fresh.className = "pill pill-warn";
      fresh.textContent = "stale (" + fmtDuration(ageSec) + " old)";
      showBanner("Host snapshot is stale (" + fmtDuration(ageSec) + " old). Check hogman-ops-snapshot.timer.", false);
    } else {
      fresh.className = "pill pill-ok";
      fresh.textContent = "updated " + ageSec + "s ago";
      showBanner("", false);
    }

    $("kpi-capacity").textContent = (cap.live || 0) + " / " + (cap.max || 0);
    $("kpi-capacity-sub").textContent =
      (cap.sleeping || 0) + " sleeping · " + (cap.renew_only || 0) + " renew-only (reserve " + (cap.renew_reserve || 0) + ")";

    $("kpi-ram").textContent = fmtBytes(host.ram_used_bytes || 0) + " / " + fmtBytes(host.ram_total_bytes || 0);
    setBar($("bar-ram"), host.ram_used_bytes || 0, host.ram_total_bytes || 0);
    $("kpi-swap-sub").textContent =
      "Swap: " + fmtBytes(host.swap_used_bytes || 0) + " / " + fmtBytes(host.swap_total_bytes || 0);

    $("kpi-disk").textContent = fmtBytes(host.disk_used_bytes || 0) + " / " + fmtBytes(host.disk_total_bytes || 0);
    setBar($("bar-disk"), host.disk_used_bytes || 0, host.disk_total_bytes || 0);
    const load = Array.isArray(host.load) ? host.load.map((v) => Number(v).toFixed(2)).join(" ") : "—";
    $("kpi-load-sub").textContent = "Load: " + load;

    $("kpi-waitlist").textContent = String(wl.waiting || 0) + " waiting";
    const oldest = wl.waiting > 0 && wl.oldest_waiting_age_sec > 0
      ? " · oldest " + fmtDuration(wl.oldest_waiting_age_sec)
      : "";
    $("kpi-waitlist-sub").textContent = String(wl.invited || 0) + " invited" + oldest;

    $("backup-meta").textContent = host.last_backup_at
      ? "Last backup: " + host.last_backup_at
      : "Last backup: none recorded";

    const svcEl = $("services-list");
    svcEl.replaceChildren();
    const services = host.services || {};
    const names = Object.keys(services).sort();
    for (const name of names) {
      const st = services[name];
      const pill = document.createElement("span");
      pill.className = statePillClass(st);
      pill.textContent = name + ": " + st;
      svcEl.appendChild(pill);
    }

    renderPens(data.pens || []);
  }

  async function refresh() {
    try {
      const res = await fetch("/api/ops/snapshot", { cache: "no-store" });
      if (!res.ok) {
        let msg = "HTTP " + res.status;
        try {
          const body = await res.json();
          if (body && body.error) msg = body.error;
        } catch (_) {}
        showBanner("Could not load host snapshot: " + msg, true);
        return;
      }
      const data = await res.json();
      render(data);
    } catch (err) {
      showBanner("Could not reach Fleet Ops API: " + err.message, true);
    }
  }

  $("refresh-btn").addEventListener("click", refresh);
  $("pen-search").addEventListener("input", () => {
    if (latestData) renderPens(latestData.pens || []);
  });
  $("pen-state-filter").addEventListener("change", () => {
    if (latestData) renderPens(latestData.pens || []);
  });

  refresh();
  setInterval(refresh, POLL_MS);
})();
