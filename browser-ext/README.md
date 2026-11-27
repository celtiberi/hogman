# Hogman Browser Extension

Minimal Manifest V3 browser extension for Chrome, Brave, Edge, Arc, Vivaldi, Chromium, Firefox (128+), and LibreWolf that routes your Hogman pen sites (`*.pens.hogman.network`) straight to your local `hogman` proxy — even while an OS VPN (ProtonVPN, Mullvad, corporate VPNs) is connected and overriding macOS system proxy settings.

> **Status:** Published on the Chrome Web Store (`mgokdogedagoejnjmjpmbcmicbmhplkk`), with Firefox Add-ons (AMO, `hogman-browser@hogman.network`) review pending. Developers can also build and load unpacked builds locally from `browser-ext/dist/` using the steps below.
>
> **Scope (hosted `*.pens.hogman.network` only):** The published store builds cover hosted `*.pens.hogman.network` pens exclusively so extension permissions stay minimal (no `<all_urls>`). Pens on any other domain (such as staging environments or custom/self-hosted domains) are ignored by the store build — use the automatic proxy URL (`proxy.pac`) method, or build an unpacked staging extension with `--zone-suffix` below.

Ordinary browsing is never routed through Hogman: non-pen traffic returns `DIRECT` (on Chrome/Brave/Edge) or passes through untouched (on Firefox), so it continues riding through your VPN as normal.

## How it works

1. `hogman` installs a read-only user-space Native Messaging host (`hogman-native-host`, `network.hogman.browser`) with no `sudo`.
2. The extension asks the native host for installed pens (`zone`, loopback `127.0.0.1:17000-26999` port, and HMAC-verified liveness).
3. The extension validates every zone and port itself and builds its own fail-closed routing rules in memory — it never downloads or evaluates remote PAC scripts.
4. **Fail-closed everywhere:** in every controllable state (no host, zero pens, paused, disabled pen, squatted port, or unknown pen), `pens.hogman.network` and `*.pens.hogman.network` route to `127.0.0.1:1` (never `DIRECT`), so pen hostnames never leak to public DNS.
5. **Per-profile allowlist by default (D-19):** each browser profile starts with an empty allowlist (`enabledZones: {}`). No pen routes in a browser profile until you explicitly enable that pen in that profile's popup, keeping mutually untrusted pens isolated across browser profiles.
6. **Proxy conflict safety:** on Chromium, the extension checks `chrome.proxy.settings.get({})` (`levelOfControl`) and the native host's OS-proxy check before applying its PAC, refusing to silently overwrite another VPN/proxy extension or corporate OS proxy.
7. **Firefox Private Windows:** Firefox disables extensions in Private Windows by default. Pen names opened in a Private Window go to public DNS unless you enable **"Run in Private Windows"** for Hogman in Add-ons.

## Permissions

- **Chrome / Brave / Edge:** `proxy`, `nativeMessaging`, `storage` (no `host_permissions`, no `<all_urls>`, no `tabs`, no `cookies`, no `webRequest`).
- **Firefox (128+):** `proxy`, `nativeMessaging`, `storage`, and `host_permissions` scoped strictly to `*://*.pens.hogman.network/*` and `*://pens.hogman.network/*` (required by Firefox for `browser.proxy.onRequest` URL filtering). Declares `data_collection_permissions: { required: ["none"] }`.

## Build and test

Requires Python 3 and Node.js (zero third-party runtime dependencies):

```bash
node --test browser-ext/test/*_test.mjs
python3 browser-ext/build.py
```

`build.py` creates unpacked directories under `browser-ext/dist/chrome/` and `browser-ext/dist/firefox/` plus reproducible archives (`hogman-ext-chrome.zip`, `hogman-ext-firefox.zip`) and `SHA256SUMS`.

## Local developer install

1. Run `python3 browser-ext/build.py`.
2. **Chrome / Brave / Edge:**
   - Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select `browser-ext/dist/chrome/`.
   - Copy the assigned 32-character extension ID and register it with the native host:
     ```bash
     ~/hogman browser-setup --chrome-id <32-char-id>
     ```
   - Open the Hogman extension popup and toggle ON the pen(s) you want in that browser profile.
3. **Firefox (128+) / LibreWolf:**
   - Ensure the native messaging host is registered (`hogman-browser@hogman.network` is already included in `hogman`'s default Firefox allowlist):
     ```bash
     ~/hogman browser-setup
     ```
   - Open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on**, and select `browser-ext/dist/firefox/manifest.json`.
   - Note: Firefox removes temporary add-ons when the browser restarts (until a signed AMO build is installed). Open the Hogman popup and enable the pen(s) you want in that profile.

## Staging / custom-domain unpacked test build

To test the extension against a non-production pens zone (without widening the published store build's permissions), pass `--zone-suffix` to `build.py`:

```bash
python3 browser-ext/build.py --zone-suffix pens.staging.example
```

This creates **unpacked-only** builds (`Hogman (staging)`) under `browser-ext/dist/staging/chrome/` and `browser-ext/dist/staging/firefox/` — no `.zip` archives or `SHA256SUMS` are produced, and `browser-ext/src/` is never modified. Its `HOSTED_ZONE_RE`, Firefox `host_permissions`, fail-closed PAC rule, and popup labels are scoped exclusively to `*.<zone-suffix>`.

1. Load the unpacked directory into a **separate browser profile** so staging pens stay isolated from production profiles.
2. Explicitly register the staging extension ID with the native messaging host (staging IDs are never allowed by default):
   - Chrome / Chromium: copy the 32-character unpacked ID from `chrome://extensions` and run:
     ```bash
     ~/hogman browser-setup --chrome-id <32-char-id>
     ```
   - Firefox: register the staging Gecko ID printed by `build.py`:
     ```bash
     ~/hogman browser-setup --firefox-id hogman-browser-staging@pens.staging.example
     ```
