# Hogman Browser Extension

Minimal Manifest V3 browser extension for Chrome, Brave, Edge, and Firefox that routes your Hogman pen sites (`*.pens.hogman.network`) straight to your local `hogman-join` proxy — even while an OS VPN (ProtonVPN, Mullvad, corporate VPNs) is connected and overriding macOS system proxy settings.

Ordinary browsing is never routed through Hogman: non-pen traffic returns `DIRECT` (on Chrome/Brave/Edge) or passes through untouched (on Firefox), so it continues riding through your VPN as normal.

## How it works

1. `hogman-join` installs a read-only user-space Native Messaging host (`hogman-native-host`, `network.hogman.browser`) with no `sudo`.
2. The extension asks the native host for installed pens (`zone`, loopback `127.0.0.1:17000-26999` port, and HMAC-verified liveness).
3. The extension validates every zone and port itself and builds its own fail-closed routing rules in memory — it never downloads or evaluates remote PAC scripts.
4. **Per-profile pen isolation (D-19):** each browser profile stores its own enabled/disabled pen list (and optional "Lock profile" mode), failing closed on disabled pens so separate browser profiles stay isolated across mutually untrusted pens.
5. **Proxy conflict safety:** on Chromium, the extension checks `chrome.proxy.settings.get({})` (`levelOfControl`) and the native host's OS-proxy check before applying its PAC, refusing to silently overwrite another VPN/proxy extension or corporate OS proxy.

## Permissions

- **Chrome / Brave / Edge:** `proxy`, `nativeMessaging`, `storage` (no `host_permissions`, no `<all_urls>`, no `tabs`, no `cookies`, no `webRequest`).
- **Firefox:** `proxy`, `nativeMessaging`, `storage`, and `host_permissions` scoped strictly to `*://*.pens.hogman.network/*` (required by Firefox for `browser.proxy.onRequest` URL filtering).

## Build and test

Requires Python 3 and Node.js (zero third-party runtime dependencies):

```bash
node --test browser-ext/test/pac_test.mjs
python3 browser-ext/build.py
```

`build.py` creates unpacked directories under `browser-ext/dist/chrome/` and `browser-ext/dist/firefox/` plus reproducible archives (`hogman-ext-chrome.zip`, `hogman-ext-firefox.zip`) and `SHA256SUMS`.

## Local unpacked testing

1. Run `python3 browser-ext/build.py`.
2. **Chrome / Brave / Edge:** open `chrome://extensions`, enable Developer mode, click **Load unpacked**, select `browser-ext/dist/chrome/`, copy the assigned 32-character extension ID, and run:
   ```bash
   ~/hogman-join browser-setup --chrome-id <32-char-id>
   ```
3. **Firefox:** open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on**, and select `browser-ext/dist/firefox/manifest.json` (`hogman-join` registers `hogman-browser@hogman.network` automatically).
