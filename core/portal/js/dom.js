// Shared DOM, formatting, clipboard, QR, and two-press confirmation helpers.

export function el(doc, tag, cls, text) {
  const node = doc.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function replaceLinks(doc, container, items, sep) {
  if (!container) return;
  container.replaceChildren();
  items.forEach(([label, href], idx) => {
    if (sep && idx > 0) container.append(doc.createTextNode(sep));
    const a = doc.createElement('a');
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = label;
    container.append(a);
  });
}

export function formatTimestamp(unixSec) {
  return new Date(unixSec * 1000).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

export function relativeTime(iso, nowMs = Date.now()) {
  if (!iso) return '';
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return '';
  const diff = Math.max(0, Math.floor((nowMs - ms) / 1000));
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  const days = Math.floor(diff / 86400);
  if (days < 30) return `${days}d ago`;
  return new Date(ms).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

export function presenceBadge(doc, online, lastSeen, nowMs = Date.now()) {
  if (typeof online !== 'boolean') return null;
  const span = el(doc, 'span', online ? 'presence online' : 'presence offline');
  const dot = el(doc, 'span', 'presence-dot');
  dot.setAttribute('aria-hidden', 'true');
  span.append(dot);
  if (online) {
    span.append(doc.createTextNode('online'));
  } else {
    const ago = relativeTime(lastSeen, nowMs);
    span.append(doc.createTextNode(ago ? `offline · ${ago}` : 'offline'));
  }
  return span;
}

export function setQR(img, svg, show) {
  if (show && svg) {
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
    img.hidden = false;
  } else {
    img.removeAttribute('src');
    img.hidden = true;
  }
}

export async function copyToClipboard(text, btn, clipboard = globalThis.navigator?.clipboard) {
  try {
    await clipboard.writeText(text);
    btn.textContent = 'Copied';
  } catch (_) {
    btn.textContent = 'Copy failed';
  }
}

export function showErrorIn(doc, id, err) {
  const p = doc.getElementById(id);
  p.textContent = err && err.message ? err.message : String(err);
  p.hidden = false;
}

// Two presses instead of a browser dialog, scoped to the exact connected button
// element so a list re-render never causes a brand-new button to fire on 1st click.
export function createPressTwice({
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = id => clearTimeout(id),
  timeoutMs = 5000,
} = {}) {
  const armed = new Map();

  return function pressTwice(key, btn, warn) {
    const existing = armed.get(key);
    if (existing) {
      clearTimer(existing.tid);
      armed.delete(key);
      if (existing.btn === btn && btn.isConnected) {
        btn.textContent = existing.was;
        btn.classList.remove('armed');
        return true;
      }
      if (existing.btn && existing.btn.isConnected) {
        existing.btn.textContent = existing.was;
        existing.btn.classList.remove('armed');
      }
    }
    const was = btn.textContent;
    btn.textContent = warn;
    btn.classList.add('armed');
    const tid = setTimer(() => {
      armed.delete(key);
      if (btn.isConnected) {
        btn.textContent = was;
        btn.classList.remove('armed');
      }
    }, timeoutMs);
    armed.set(key, { tid, btn, was });
    return false;
  };
}
