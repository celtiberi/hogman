# Keeper Passkey Recovery & Threat Model (D-12)

Status: draft, revision 2 — folds in red-team findings on PR #39. Ready for second look before any code. P1, decision D-12.

## 1. Problem & Goals

A Hogman pen runs on its own control plane (`registrar` + `headscale` + `edge`) behind a public host (`PUBLIC_HOST`, for example `bobo.pens.example` or `hs.example.com`) and a private mesh zone (`Zone`, for example `bobo.hogman`). Keepers (`owner` and `admin` members) administer the pen over the mesh at `https://home.<zone>`.

If a keeper loses every enrolled device at once (laptop stolen, phone wiped, core host still running), they lose mesh access and can no longer open `home.<zone>` to mint a replacement `/join` link. Per decision **D-12**, Hogman solves this with **keeper passkeys only, with zero operator recovery**:

- There is no operator or host support path to bypass authentication, reset keeper state, or mint a device key from a dashboard ticket.
- There are no passwords, email/SMS reset codes, TOTP seeds, static printable backup codes, or third-party OIDC logins (no Google/GitHub sign-in).
- A keeper registers one or more WebAuthn discoverable passkeys (for example in a synced password manager vault such as Bitwarden or iCloud Keychain, or on a hardware security key) tied to `<PUBLIC_HOST>`.
- Visiting `https://<PUBLIC_HOST>/recover` and presenting a valid registered keeper passkey mints **one** single-use, short-lived `kind="personal"` keeper device link (`https://<PUBLIC_HOST>/join#k=<key>&fp=<rootFP>`), which admits one replacement device back onto the pen under a 72-hour security cool-off.

Non-goals for this design:
- **Self-service recovery for non-keeper members (`role = "member"`):** regular members ask a keeper on the pen for a new `/join` link.
- **Remote device wiping from `/recover`:** `/recover` only restores access to one replacement device under a 72-hour cool-off. Reviewing and removing lost devices from the recovered device happens on `home.<zone>` once the cool-off expires (or immediately via another keeper or a pre-existing keeper device).
- **Protection against compromise of the registrar host or TLS private key:** whoever controls the registrar process or its SQLite database can call Headscale directly.

## 2. Standards & Library Choice

This design targets the following normative references and known WebAuthn pitfalls:

- **W3C WebAuthn Level 3:**
  - Discoverable credentials (`residentKey: "required"`, `userVerification: "required"`) so recovery ceremonies require no handle input and expose no account-existence oracle.
  - Strict relying party ID (`RPID`) and exact origin validation matching browser Same-Origin / effective-domain rules (`Section 5.4`, `Section 7.1`, `Section 7.2`).
  - Explicit rejection of cross-origin assertions (`crossOrigin == false`), explicit user presence (`UP == 1`) and user verification (`UV == 1`) flag enforcement, Backup Eligibility (`BE`) / Backup State (`BS`) tracking, and `signCount` clone checks appropriate for synced vs. device-bound authenticators.
- **NIST SP 800-63B-4 (July 2025):**
  - **Appendix B (Syncable Authenticators) & Section 4:** Syncable passkeys (`BE == 1`, `UV == 1`, protected by an encrypted vault sync fabric with MFA) satisfy **AAL2** and are allowed by default so keepers can recover even if their phone and laptop are lost together. Device-bound authenticators (`BE == 0`, such as hardware FIDO2 keys) satisfy **AAL3**.
  - **Recovery & Event Notification (Section 4):** Rejects knowledge-based authentication (KBA), SMS, and email fallback channels; requires re-verification of authorization state, strict rate limiting, audit logging of credential enrollment/use, and visibility on the authenticated management surface (`home.<zone>`) so keepers spot unexpected recovery events.
- **OWASP Authentication & Session Management Cheat Sheets:**
  - Uniform generic errors on public endpoints to prevent user or credential enumeration.
  - Cryptographically random single-use challenges and setup tokens (`>= 256` bits), short TTLs, atomic single-use consumption in SQLite, fail-closed authorization checks, and strict anti-framing / `Referrer-Policy` / `Cache-Control: no-store` headers.
- **2026 WebAuthn Library Origin & RP-ID Bug Class (`CVE-2026-30964` and siblings):**
  - `CVE-2026-30964` (`web-auth/webauthn-lib < 5.2.4`) demonstrated how origin allowlist checks that reduce an origin URL to its hostname alone silently accept wrong schemes (`http://`) or unexpected ports (`:8443`).
  - Sibling flaws in other stacks (including `webauthn-rs-core` dot-prefix RP ID boundary bugs and libraries missing `crossOrigin` checks) allowed subdomain/prefix spoofing or embedded-iframe assertions when RP ID matching was implemented permissively.
- **Go Library Choice:**
  - Pin **`github.com/go-webauthn/webauthn >= v0.18`** inside `core/registrar/go.mod`. It is pure Go (preserving `CGO_ENABLED=0` static builds in Docker and CI), supports WebAuthn Level 3 `BE`/`BS` flags and `CloneWarning`, enforces exact scheme+host+port origin matching, and validates `crossOrigin`.
  - Construct the WebAuthn verifier **once at startup** in `NewService` from `cfg.PublicHost` (never dynamically from incoming `Host` or `Origin` request headers).

## 3. Architecture & Flows

### 3.1 The Cross-Origin RP-ID Constraint (`home.<zone>` vs. `<PUBLIC_HOST>`)

Keepers administer their pen over the mesh at `https://home.<zone>` (for example `https://home.bobo.hogman`), while locked-out recovery must happen from the public internet at `https://<PUBLIC_HOST>/recover` (for example `https://bobo.pens.example/recover`).

Per W3C WebAuthn Level 3 (`Section 5.4`), `navigator.credentials.create` only succeeds if the caller page's origin has an effective domain equal to `rp.id` or a subdomain of `rp.id`. A page at `https://home.bobo.hogman` **cannot** register a credential with `rp.id = "bobo.pens.example"` — the browser throws `SecurityError`. Conversely, registering under `bobo.hogman` is unusable during recovery because a locked-out browser on the public internet cannot reach `.hogman`, and private mesh TLDs cannot participate in public Related Origin Requests (`/.well-known/webauthn`).

**Solution:** Use a short-lived, mesh-minted setup handoff:

1. **Enrollment always starts on the authenticated mesh (`https://home.<zone>`):** `home.<zone>` proves who the keeper is via Tailscale/Headscale identity (`identify`) and mints a single-use `setup_token`.
2. **Enrollment finishes on `https://<PUBLIC_HOST>/recover/setup#t=<setup_token>`:** the browser executes `navigator.credentials.create` on `<PUBLIC_HOST>` itself, where `origin == "https://" + PUBLIC_HOST` and `rp.id == host(PUBLIC_HOST)` match natively.
3. **Management stays mesh-only:** listing, renaming, and deleting registered passkeys live exclusively behind `MeshHandler` on `home.<zone>`. Public endpoints on `<PUBLIC_HOST>` can never list or delete passkeys.

### 3.2 Passkey Enrollment Flow (`home.<zone>` -> `/recover/setup`)

```
Keeper browser (on mesh)                core/registrar                   Edge Caddy (<PUBLIC_HOST>)
  |                                           |                                 |
  | 1. Click "Add a recovery passkey"         |                                 |
  | POST https://home.<zone>/api/passkeys/setup                                 |
  | (MeshHandler: loopback+XFF active keeper) |                                 |
  |------------------------------------------>|                                 |
  |   mints 256-bit setup_token (5m TTL)      |                                 |
  |   stores SHA-256(token) in passkey_setups |                                 |
  |   returns setup URL with #t=<setup_token> |                                 |
  |<------------------------------------------|                                 |
  |                                                                             |
  | 2. Open https://<PUBLIC_HOST>/recover/setup#t=<setup_token>                 |
  |---------------------------------------------------------------------------->|
  |   serves static SPA (Referrer-Policy: no-referrer, CSP, X-Frame-Options: DENY)
  |<----------------------------------------------------------------------------|
  |                                                                             |
  | 3. POST /hogman/v1/recover/register/begin  {"setup_token":"...","label":"..."}
  |------------------------------------------>|                                 |
  |   validates & atomically consumes         |                                 |
  |   setup_token; creates 120s register      |                                 |
  |   challenge bound to member_id            |                                 |
  |   returns WebAuthn creation options       |                                 |
  |<------------------------------------------|                                 |
  |                                                                             |
  | 4. navigator.credentials.create(...)                                        |
  |    (rp.id=<RPID>, residentKey=required, uv=required)                        |
  |                                                                             |
  | 5. POST /hogman/v1/recover/register/finish {"challenge_id":"...","credential":...}
  |------------------------------------------>|                                 |
  |   consumes challenge, verifies origin/RPID/UP/UV/flags,                     |
  |   inserts row into passkeys, writes audit |                                 |
  |<------------------------------------------|                                 |
```

Design notes for enrollment:
- **Fragment transport (`#t=<setup_token>`):** Putting `setup_token` in the URL fragment prevents browsers from sending the secret in the initial HTTP `GET /recover/setup` request line, Caddy access logs, or `Referer` headers.
- **Ceremony parameters:**
  - `rp.id`: hostname of `cfg.PublicHost` (via `net.SplitHostPort` fallback if a port is present).
  - `user.id`: opaque 32-byte random `members.webauthn_user_id` (not `members.id`, `handle`, or `hs_user_id`).
  - `user.name` / `user.displayName`: `<handle>` (e.g. `alice`) and `<handle> (<Zone>)` so the keeper recognizes which pen the passkey belongs to in their vault.
  - `authenticatorSelection`: `residentKey: "required"`, `requireResidentKey: true`, `userVerification: "required"`, and `authenticatorAttachment` omitted (allows both synced vaults and roaming hardware keys).
  - `attestation: "none"` to minimize metadata fingerprinting while still recording `BE`, `BS`, `aaguid` (if present), and `transports`.
  - Per-keeper cap: reject registration if the member already has 10 registered passkeys (`MaxPasskeysPerMember = 10`).
- **One-shot transition:** `POST /hogman/v1/recover/register/begin` atomically sets `passkey_setups.consumed_at` inside a SQLite transaction before returning the 120-second `recover_challenges` row. If the keeper cancels the WebAuthn prompt or closes the tab, they simply click **Add a recovery passkey** on `home.<zone>` again.

### 3.3 Mesh-Only Management (`home.<zone>` / `core/portal`)

Additions to `MeshHandler(s *Service)` (wrapped by `identify(s, requireSameOriginAndJSON(s.cfg.Zone, mux))`):

- `GET /api/me` (addition):
  - For active keepers, include `passkey_count`, `in_cooloff` / `cooloff_until` (if the calling device joined via recovery within 72h), and the shared `security_events` feed (`passkey_added`, `recover_mint`, `recover_cancelled`, `recover_clone_warning`) visible to **all active keepers (`owner` + `admin`)**.
  - For any active member device on `home.<zone>`, include `active_recoveries` and `security_events` affecting their own membership so **all other devices of the recovering member** immediately see recovery alerts and cancellation controls too.
- `GET /api/passkeys`: requires `actor.IsAdmin()` (`owner` or `admin`). Lists only the caller's own passkeys: `id`, `label`, `synced` (`backup_eligible`), `backed_up` (`backup_state`), `clone_flagged_at`, `created_at`, `last_used_at`. Credential IDs and public keys never leave the registrar.
- `POST /api/passkeys/setup`: requires `actor.IsAdmin()` and **not in 72h recovery cool-off**. Lazily assigns `members.webauthn_user_id` if null, prunes expired `passkey_setups` rows, enforces the passkey cap, stores `SHA-256(token)` with `now + 5m`, audits `passkey_setup_created`, and returns `{"setup_url": "https://" + s.cfg.PublicHost + "/recover/setup#t=" + token, "expires_at": ...}`.
- `POST /api/passkeys/rename`: requires `actor.IsAdmin()` and **not in 72h recovery cool-off**. Body `{"id": ..., "label": ...}`, verifies ownership (`member_id = actor.Member.ID`), updates trimmed label (max 64 bytes), audits `passkey_renamed`.
- `POST /api/passkeys/delete`: requires `actor.IsAdmin()` and **not in 72h recovery cool-off**. Body `{"id": ...}`, verifies ownership (`member_id = actor.Member.ID`), deletes row, audits `passkey_deleted`. Using `POST` with JSON bodies ensures every mutating endpoint obeys `requireSameOriginAndJSON` (`Sec-Fetch-Site`, `Origin`, `Content-Type: application/json`), blocking `.hogman` sibling CSRF.
- `POST /api/recoveries/cancel`: body `{"device_key_id": ...}` or `{"device_id": ...}` (cancelling an active recovery; see Section 3.5).

In `core/portal/index.html` and `core/portal/portal.js`:
- Add a **Recovery passkeys** subsection visible only to keepers (`me.is_admin || me.is_owner`), showing each registered passkey's `label`, a `synced` vs. `device-bound` badge derived from `backup_eligible`, a clear **Clone suspected — remove and re-register** badge if `clone_flagged_at` is set, timestamps, and the existing inline double-click removal confirmation pattern.
- Display the shared **Security events & active recoveries** banner in `#mine` / `#herd` for `passkey_added`, `recover_mint`, `recover_cancelled`, and `recover_clone_warning`, with an inline **Cancel recovery** button for eligible pre-existing devices / co-keepers and a read-only countdown notice when the current device is inside its 72-hour cool-off.
- All dynamic strings rendered strictly via `textContent` (no `innerHTML`).

### 3.4 Public Recovery Ceremony (`<PUBLIC_HOST>/recover`)

1. Keeper visits `https://<PUBLIC_HOST>/recover` from any browser with access to their passkey vault or security key.
2. Page clicks **Recover device access** -> sends `POST /hogman/v1/recover/begin` with `{}` (`Content-Type: application/json`, strict `decodeJSON` `DisallowUnknownFields`). No username or handle field exists.
3. Registrar generates a 256-bit challenge (`kind = "assert"`, 120s TTL), saves the WebAuthn session state in `recover_challenges`, and returns `CredentialRequestOptions` with `rpId`, `userVerification: "required"`, and **empty `allowCredentials`**.
4. Browser calls `navigator.credentials.get(...)`, presents matching discoverable passkeys for `<RPID>`, verifies user presence and user verification locally, and signs the challenge.
5. Browser sends `POST /hogman/v1/recover/finish` with `{"challenge_id": "...", "credential": ...}`.
6. Inside `s.mu` / SQLite serialized transaction, registrar:
   - Atomically consumes the `recover_challenges` row (`UPDATE ... SET consumed_at = ? WHERE id = ? AND kind = 'assert' AND consumed_at IS NULL AND expires_at > ?`).
   - Resolves the passkey + owning member via `userHandle` (`members.webauthn_user_id`) and `credential_id`. Rejects if `passkeys.clone_flagged_at IS NOT NULL`.
   - Verifies the WebAuthn assertion via `go-webauthn` (`RPID`, `Origin`, `crossOrigin == false`, `UP == 1`, `UV == 1`, signature, algorithm, `signCount` / `CloneWarning`).
   - If `CloneWarning` triggers: sets `passkeys.clone_flagged_at = now`, logs `recover_clone_warning` to `audit` (surfaced in `security_events` to all keepers on `home.<zone>`), and returns `401` (`{"error": "recovery could not be verified"}`).
   - Re-checks live member state: rejects if `member.Status != "active"` or `member.Role NOT IN ("owner", "admin")`.
   - Checks active cool-off / open recovery key state: rejects with `401` (logs `recover_blocked_cooloff`, **does not consume** the 3/24h quota) if the member already has a live device within its 72-hour cool-off (`devices.recovered_at IS NOT NULL AND now < recovered_at + 72h`) or an unused unrevoked unexpired recovery key in `device_keys` (`recovery_passkey_id IS NOT NULL`).
   - Enforces the per-keeper recovery mint quota (**3** recovery mints per `24h` rolling window) and existing `MaxOpenDeviceKeys`.
   - Updates `passkeys.sign_count`, `backup_state`, and `last_used_at`.
   - Mints **one** `kind="personal"` Headscale pre-auth key with a **15-minute** TTL (`RecoveryKeyTTL = 15 * time.Minute`) and stamps `device_keys.recovery_passkey_id = passkey.id`.
   - Writes a `recover_mint` audit row (identifying handle, passkey label, `BE`/`BS`, and source IP; visible to all keepers and all of the member's devices on `home.<zone>`).
   - Returns `{"link": s.DeviceLink(key, "personal"), "expires_at": ..., "handle": m.Handle}`.
7. On any failure (bad signature, expired/replayed challenge, cloned counter, active cool-off, demoted/suspended/removed member, quota exceeded), registrar logs the reason to `audit` and returns HTTP `401` with a uniform generic JSON error (`{"error": "recovery could not be verified"}`) — never revealing whether a passkey exists or why a member failed policy.
8. Keeper follows the returned `/join#k=...&fp=...` link to enroll their replacement device. `Sync()` detects `k.RecoveryPasskeyID != nil` on the newly created key and stamps `devices.recovered_at = now` and `devices.recovery_passkey_id = k.RecoveryPasskeyID`.

### 3.5 Post-Recovery 72-Hour Cool-Off & Cancellation

A device joined through `/recover` is immediately a keeper for day-to-day mesh access (`portal` browsing, shares, normal apps), **but cannot perform pen-takeover or privilege-laundering actions for 72 hours** (`RecoveryCooloff = 72 * time.Hour`):

- **Device attribution in `Actor`:** `identify` in `core/registrar/http.go` already receives `(member, device, err)` from `s.VerifyLiveCaller(r.Context(), ip)`. It attaches `Device: device` onto `Actor`.
- **Blocked during 72-hour cool-off (`a.Device != nil && a.Device.RecoveredAt != nil && now < *a.Device.RecoveredAt + 72h`):** server-side handlers reject with HTTP `403` whenever the calling device attempts:
  - adding, renaming, or deleting passkeys (`/api/passkeys/setup`, `/api/passkeys/rename`, `/api/passkeys/delete`);
  - changing member roles (`SetRole`);
  - suspending or removing members (`Suspend`, `Kick`);
  - removing any device other than itself (`RemoveDevice` where `id != a.Device.ID`);
  - minting invites or adding members (`MintInvite`, `AddMember`) — closes creating a side-door admin account during cool-off;
  - minting new device keys (`IssueDeviceKey`) — closes enrolling an un-stamped child device without `recovered_at` to launder cool-off restrictions;
  - cancelling a recovery (`POST /api/recoveries/cancel`).
- **Allowed during cool-off:** removing its own device (`RemoveDevice` where `id == a.Device.ID`), leaving the pen, claiming/using normal services, and viewing `home.<zone>`.
- **Blocked from re-recovering:** while a member has a live device inside its 72-hour cool-off (or an open unused recovery `device_key`), `/hogman/v1/recover/finish` refuses further recovery attempts (`401`, logs `recover_blocked_cooloff`, without counting against the 3/24h quota).
- **Shared notifications:** `passkey_added`, `recover_mint`, `recover_cancelled`, and `recover_clone_warning` appear in `GET /api/me` (`security_events`) for **all active keepers (`owner` + `admin`)**, and recovery events also appear to **all other live devices of the recovering member** on `home.<zone>`.
- **Cancellation (`POST /api/recoveries/cancel`):**
  - Authorized callers: any active keeper (`owner` or `admin`) on a device **not** inside a 72-hour cool-off (and created at or before the target recovery timestamp), OR any pre-existing non-cool-off device belonging to the recovering member itself.
  - Inside `s.mu` + SQLite transaction:
    1. Expires/revokes any open unused recovery `device_keys` row for that recovery event (`hs.ExpireKey` + `RevokeDeviceKey`).
    2. If the recovered device has already joined, removes it from Headscale (`hs.DeleteNode`), deletes its `names`, marks it removed in `devices`, and re-applies ACL policy (`s.applyPolicy`).
    3. **Deletes the `passkeys` row referenced by `recovery_passkey_id`** (and any active `passkey_setups` / `recover_challenges` for that member) so the compromised passkey is burned permanently.
    4. Writes a `recover_cancelled` audit event (surfacing in `security_events` to all keepers).

### 3.6 Caddy Routing & Headers (`core/config/edge.Caddyfile` & `deploy/hogman-host`)

Both Caddy edge templates (`core/config/edge.Caddyfile` for self-hosted cores and the `(pen)` snippet in `deploy/hogman-host` for hosted pens) must route:

- Static SPAs at `/recover`, `/recover/setup`, and `/recover/assets/*` with the same security headers used for `/join`:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store`
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
- JSON API endpoints `/hogman/v1/recover/register/begin`, `/hogman/v1/recover/register/finish`, `/hogman/v1/recover/begin`, `/hogman/v1/recover/finish`:
  - Matched under the existing `/hogman/*` Caddy reverse proxy (`request_body { max_size 16KB }`) forwarding trusted `X-Forwarded-For` to `PublicHandlerWithRateLimit`.
  - Protected in `PublicHandlerWithRateLimit` by a tighter IP limiter than `/redeem` (proposed: `10` requests per minute per client IP on recovery endpoints) in addition to per-member recovery mint quotas.

### 3.7 SQLite Schema & Transactional Cleanup (`core/registrar/store.go`)

Added via an idempotent migration helper in `OpenStore` (following `migrateNamesNote`):

```sql
ALTER TABLE members ADD COLUMN webauthn_user_id BLOB;
CREATE UNIQUE INDEX IF NOT EXISTS idx_members_webauthn_user_id
  ON members(webauthn_user_id) WHERE webauthn_user_id IS NOT NULL;

ALTER TABLE device_keys ADD COLUMN recovery_passkey_id INTEGER REFERENCES passkeys(id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN recovered_at INTEGER;
ALTER TABLE devices ADD COLUMN recovery_passkey_id INTEGER REFERENCES passkeys(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS passkeys (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id        INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  credential_id    BLOB NOT NULL UNIQUE,
  public_key       BLOB NOT NULL,
  attestation_type TEXT NOT NULL DEFAULT '',
  aaguid           BLOB,
  sign_count       INTEGER NOT NULL DEFAULT 0,
  backup_eligible  INTEGER NOT NULL DEFAULT 0,
  backup_state     INTEGER NOT NULL DEFAULT 0,
  transports       TEXT NOT NULL DEFAULT '',
  label            TEXT NOT NULL DEFAULT '',
  created_at       INTEGER NOT NULL,
  last_used_at     INTEGER,
  clone_flagged_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_passkeys_member_id ON passkeys(member_id);

CREATE TABLE IF NOT EXISTS passkey_setups (
  token_hash  BLOB PRIMARY KEY,
  member_id   INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE TABLE IF NOT EXISTS recover_challenges (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('register', 'assert')),
  member_id    INTEGER REFERENCES members(id) ON DELETE CASCADE,
  session_json TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  consumed_at  INTEGER
);
```

Notes:
- `OpenStore` runs SQLite with `WAL`, `busy_timeout(5000)`, `foreign_keys(1)`, and `SetMaxOpenConns(1)`.
- Expired rows in `passkey_setups` and `recover_challenges` are pruned on each write to keep table size bounded.
- **Transactional surface removal on demotion, suspension, or removal:** When `SetRole` demotes a keeper to `member`, `Suspend` suspends a keeper, or `Kick` removes a keeper, `registrar` deletes all of that member's `passkeys`, `passkey_setups`, and `recover_challenges` rows **in the same SQLite transaction** as the role/status change (while `device_keys.recovery_passkey_id` and `devices.recovery_passkey_id` use `ON DELETE SET NULL` to preserve device/audit history). The live `status == 'active' && role IN ('owner', 'admin')` check in `/recover/finish` remains as a second guard. A suspended keeper who is later resumed (`Resume`) must re-enroll a fresh passkey on `home.<zone>`.
- Registration (`register/finish`) writes a `passkey_added` audit record (`handle`, `label`, `synced` vs. `device-bound`), surfaced in `security_events` to all keepers on `home.<zone>`.

## 4. Verification Invariants & Mandatory Negative Unit Test Matrix

### 4.1 Code Invariants (Must Hold in `core/registrar`)

1. **Static RP configuration:** `RPID` (extracted hostname of `cfg.PublicHost`, ignoring `:port` only for `RPID`, never empty, never containing wildcards or leading `.`) and `RPOrigins` (`[]string{"https://" + cfg.PublicHost}`) are constructed once in `NewService` and verified in unit tests. Request `Host`, `Origin`, `X-Forwarded-Host`, and `Referer` headers never configure the verifier.
2. **Exact origin match:** Scheme (`https`), hostname, and implicit/explicit port must match `https://<cfg.PublicHost>` verbatim.
3. **Mandatory user flags:** Both `Flags.UserPresent` (`UP`) and `Flags.UserVerified` (`UV`) must be `true` on both registration and assertion.
4. **No cross-origin assertions:** Reject any `clientDataJSON` with `crossOrigin: true`.
5. **Algorithm allowlist:** Accept only strong modern COSE algorithms configured on the server (`ES256` / `-7`, `EdDSA` / `-8`, `RS256` / `-257`). Reject `none` or downgraded algorithms.
6. **SignCount policy (`BE` vs. hardware keys):** Per WebAuthn Level 3, synced passkeys commonly leave `signCount == 0` across devices. Only when `storedSignCount > 0 || authenticatorSignCount > 0` does a non-increasing `signCount` trigger `CloneWarning`, which **must fail closed** (`401`), set `clone_flagged_at`, and emit `recover_clone_warning` to the shared keeper feed (so an honest keeper recovers via another registered passkey and deletes the flagged key on `home.<zone>`).
7. **Atomic one-shot challenge and setup consumption:** Both `passkey_setups` consumption (on `register/begin`) and `recover_challenges` consumption (on `register/finish` and `recover/finish`) must happen via conditional `UPDATE ... WHERE consumed_at IS NULL AND expires_at > ?` checking `RowsAffected() == 1`.
8. **Live authorization + transactional cleanup:** Demotion, suspension, or removal (`SetRole`, `Suspend`, `Kick`) deletes all of that member's `passkeys`, `passkey_setups`, and `recover_challenges` rows in the same SQLite transaction; `recover/finish` also re-verifies `m.Status == "active"` and `m.Role == "owner" || m.Role == "admin"` and checks active cool-off / open recovery key state before minting.
9. **Cool-off enforcement at the service layer:** `Actor.Device` must enforce the 72-hour cool-off across `SetRole`, `Suspend`, `Kick`, `RemoveDevice` (for non-self devices), `MintInvite`, `AddMember`, `IssueDeviceKey`, `/api/passkeys/{setup,rename,delete}`, and `/api/recoveries/cancel`.

### 4.2 Mandatory Negative Test Matrix (Unit Tests Before Any Merge)

Every item below must be a concrete unit test in `core/registrar`:

| Case | Attack / Bug Modeled | Expected Result |
| --- | --- | --- |
| Origin wrong host (`https://evil.example`) | Cross-origin assertion replay | Reject `401` (`Origin` mismatch) |
| Origin wrong scheme (`http://bobo.pens.example`) | `CVE-2026-30964` host-only origin reduction | Reject `401` (`https` required) |
| Origin wrong port (`https://bobo.pens.example:8443`) | `CVE-2026-30964` port-ignoring origin check | Reject `401` (exact origin string required) |
| RP ID dot-prefix / parent (`pens.example`, `.pens.example`) | Parent-domain / dot-prefix RP ID confusion | Startup rejects invalid `RPID` or assertion fails `rpIdHash` check |
| RP ID mesh domain (`home.bobo.hogman`) | Using mesh origin inside `<PUBLIC_HOST>` ceremony | Reject `401` (`rpIdHash` & `Origin` mismatch) |
| `clientData.crossOrigin == true` | Cross-origin iframe phishing / WebAuthn library gap | Reject `401` (`crossOrigin` rejected) |
| `UP == 0` or `UV == 0` | Silent assertion without biometric/PIN verification | Reject `401` (NIST `AAL2`/`AAL3` `UV` invariant) |
| `signCount` regresses after `> 0` (`stored=5`, `got=4` or `5`) | Cloned hardware key (`CloneWarning`) | Reject `401`, sets `clone_flagged_at`, blocks future use of flagged key; keeper's 2nd passkey still recovers (`200`) |
| `signCount == 0` -> `0` on synced passkey (`BE=1`) | Normal Bitwarden / iCloud Keychain sync behavior | Accept (`200`), mint link |
| Expired challenge (`> 120s`) | Delayed replay of intercepted WebAuthn assertion | Reject `401` |
| Replayed `challenge_id` | Resubmitting already-consumed assertion | Reject `401` (second request sees `RowsAffected == 0`) |
| Parallel `recover/finish` with same `challenge_id` | TOCTOU race to mint 2 device links from 1 tap | Exactly 1 succeeds, 1 rejects `401` |
| Expired or replayed `setup_token` | Intercepted browser history / second enrollment tab | Reject `401` |
| Demoted (`member`), `suspended`, or `removed` keeper (`SetRole`, `Suspend`, `Kick`) | Stale passkey held by ex-keeper | `passkeys`, `passkey_setups`, and `recover_challenges` deleted in same SQLite txn; assertion rejects `401` |
| Non-keeper (`role = "member"`) calls `POST /api/passkeys/setup` | Privilege escalation via mesh API | Reject `403` |
| `.hogman` sibling page sends `POST /api/passkeys/setup` (`Origin: https://app.bobo.hogman`) | Non-PSL `.hogman` same-site CSRF | Reject `403` by `requireSameOriginAndJSON` |
| Unknown JSON fields or body `> 16KB` on public `/hogman/v1/recover/*` | Parameter smuggling / DoS payload | Reject `400`/`413` via `decodeJSON` |
| Recovered device inside 72h cool-off calls `/api/passkeys/delete`, `/setup`, `/rename`, `SetRole`, `Suspend`, `Kick`, `MintInvite`, `AddMember`, `IssueDeviceKey`, `POST /api/recoveries/cancel`, or `RemoveDevice` (other device) | Post-recovery pen takeover / cool-off laundering bypass | Reject `403` |
| Recovered device inside 72h cool-off calls `RemoveDevice` on its own device | Honest keeper cleans up own recovered device | Accept `200` |
| Recovery attempted while keeper is in 72h cool-off or has an open unused recovery key | Re-recovery loop / quota bypass | Reject `401` (`recover_blocked_cooloff`), does not consume 3/24h quota |
| Pre-existing non-cool-off device or co-keeper calls `POST /api/recoveries/cancel` | Aborting stolen-vault takeover | Accept `200`, revokes key / removes recovered device, deletes `recovery_passkey_id` row; re-asserting burned passkey rejects `401` |

## 5. Threat Model

**Assets:**
- Minting a `kind="personal"` Headscale pre-auth key for an active keeper (equivalent to full keeper administrative access once `/join` completes).
- Keeper passkey enrollment tokens (`setup_token`) and stored public keys.
- Pen membership metadata (handles, key presence) against public enumeration.

**Attackers:**
- **A1 — Internet attacker:** can reach `https://<PUBLIC_HOST>/recover*` and `/hogman/v1/recover/*`, spoof headers, flood requests, or phish users onto attacker-controlled domains.
- **A2 — Malicious `.hogman` app / compromised regular member on the pen:** has network access inside the pen and can host pages under `https://evil.<zone>`, send sibling-origin requests (`Sec-Fetch-Site: same-site`), or observe mesh behavior, but is not an active keeper.
- **A3 — Demoted or removed former keeper:** still holds a passkey they registered earlier while active.
- **A4 — Thief with physical/account compromise:** stole a keeper's laptop/phone or compromised their synced password manager account.

### Threats & Mitigations

**T1 — Phishing & Adversary-in-the-Middle (AiTM) Proxy (A1):**
Attacker tricks keeper into visiting `https://bobo-pens.evil.example/recover` and proxies traffic to `<PUBLIC_HOST>`.
- *Mitigation:* WebAuthn binds `rpIdHash` and `clientData.origin` inside the authenticator signature. The browser signs `bobo-pens.evil.example`, so verification against static `RPOrigins = ["https://bobo.pens.example"]` fails regardless of proxy headers. Cross-origin embedding is blocked by `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, and server-side `crossOrigin == false` verification.

**T2 — Origin / RP-ID Validation Flaws (`CVE-2026-30964` Class) (A1):**
Permissive host-only origin checks or dot-prefix RP ID checks accept wrong ports, `http://`, or attacker subdomains, or a reverse proxy injects a spoofed `Host` header.
- *Mitigation:* `RPID` and `RPOrigins` are computed strictly from `cfg.PublicHost` at startup, never from request headers. Pinned `go-webauthn >= v0.18` enforces full scheme+host+port origin equality and exact `rpIdHash` verification, backed by the mandatory negative tests in Section 4.2.

**T3 — Setup Token Interception During Mesh -> Public Handoff (A2, Local Logs):**
To solve the WebAuthn origin split (`home.<zone>` vs. `<PUBLIC_HOST>`), `home.<zone>` hands the browser a `setup_token`.
- *Mitigation:* Token is 256-bit random, stored SHA-256 hashed in `passkey_setups`, scoped strictly to enrollment (can never authenticate `/recover`), bound to a single `member_id`, expires in 5 minutes, and is consumed atomically on `register/begin`. Passing it in `#t=` prevents it from crossing the wire in HTTP `GET` logs or `Referer` headers (`Referrer-Policy: no-referrer` + `Cache-Control: no-store`).

**T4 — Cross-Site Request Forgery from `.hogman` Apps (A2):**
Because `.hogman` is not on the Public Suffix List, `https://rogue.bobo.hogman` is considered `same-site` with `https://home.bobo.hogman`.
- *Mitigation:* All `home.<zone>` passkey management endpoints (`/api/passkeys/setup`, `/rename`, `/delete`) sit inside `MeshHandler` behind `requireSameOriginAndJSON`, which strictly requires `Sec-Fetch-Site` in `{"same-origin", "none"}`, `Origin == "https://home.<zone>"`, and `Content-Type: application/json`. Using `POST` JSON even for delete avoids bodyless simple-request gaps.

**T5 — Public Handle or Passkey Enumeration Oracle (A1):**
Attacker probes `/hogman/v1/recover/*` to discover keeper usernames (`alice`), whether keepers exist, or whether a keeper has passkeys configured.
- *Mitigation:* `POST /hogman/v1/recover/begin` takes `{}` with zero identifier fields and returns empty `allowCredentials` (discoverable credential flow). `recover/finish` returns the same HTTP `401` JSON body for unknown credentials, invalid signatures, expired challenges, and rejected member status/role.

**T6 — Challenge Replay & Concurrent Double-Mint Race (A1):**
Attacker replays a captured assertion or sends parallel `recover/finish` requests from one valid signature.
- *Mitigation:* Challenges are 256-bit random with 120-second expiry and consumed via atomic single-statement `UPDATE ... WHERE consumed_at IS NULL AND expires_at > ?` inside SQLite (`SetMaxOpenConns(1)`). Only `RowsAffected() == 1` proceeds.

**T7 — Stale Passkey Used by Former / Suspended / Demoted Keeper (A3):**
An admin leaves the pen, is suspended, or is demoted to `member`, then uses an old synced passkey at `/recover`.
- *Mitigation:* `SetRole` (demotion to `member`), `Suspend`, and `Kick` delete all of that member's `passkeys`, `passkey_setups`, and `recover_challenges` rows in the **same SQLite transaction** as the role/status change (and revoke open device keys). Live verification in `recover/finish` (`members.status == 'active' AND members.role IN ('owner', 'admin')`) remains as defense in depth. Resumed keepers must re-enroll a fresh passkey on `home.<zone>`.

**T8 — Cloned Hardware Key vs. Synced Passkey Counter Semantics (A4):**
A hardware security key is cloned, or a synced passkey behaves inconsistently across devices (or a hardware authenticator exhibits a buggy counter).
- *Mitigation:* Track `backup_eligible` (`BE`), `backup_state` (`BS`), `sign_count`, and `clone_flagged_at`. Synced passkeys (`BE=1`) routinely keep `signCount == 0` per WebAuthn L3 and are accepted normally. When either stored or presented `signCount > 0` and the counter fails to strictly advance (`CloneWarning`), fail closed (`401`), set `clone_flagged_at` (blocking further use of that credential), and emit `recover_clone_warning` to all keepers on `home.<zone>`. An honest keeper with a buggy hardware counter recovers using a second registered passkey (for example their synced vault passkey) and deletes the flagged key on `home.<zone>`.

**T9 — Synced Vault Compromise, Stolen-Vault Takeover, or Single-Device Theft (A4):**
Attacker compromises the keeper's Bitwarden/iCloud account (or steals an unlocked device), mints a recovery link, joins as a keeper device, and tries to delete the real keeper's passkeys, enroll rogue passkeys, demote/remove keepers, mint fresh keys/invites, or boot out the keeper's existing devices.
- *Mitigation:*
  - `UV=1` forces device/vault verification (PIN/biometric) on top of possession.
  - Per **D-12** and **NIST SP 800-63B-4 AAL2**, keeping syncable passkeys enabled is an intentional trade-off against irreversible lockout; keepers should protect their synced vault with strong MFA.
  - **72-hour recovery cool-off + cool-off anti-laundering:** The recovered device cannot add/rename/delete passkeys, change roles, suspend/remove members, remove other devices, mint invites (`MintInvite`, `AddMember`), issue device keys (`IssueDeviceKey`), or cancel a recovery for 72 hours, and the keeper cannot trigger another recovery while cool-off or an open recovery key is active.
  - **Shared visibility & cancellation:** `recover_mint` (and `passkey_added` for early tampering warnings) appears on `home.<zone>` to **all active keepers** and **all other live devices of the recovering member**. Any non-cool-off pre-existing device of that member or any active co-keeper can click **Cancel recovery** (`POST /api/recoveries/cancel`) to immediately revoke the link/device and delete the compromised `passkeys` row. *(Trust nuance: co-keeper `admin`s can cancel an `owner`'s recovery to stop a stolen-vault takeover. Registering two independent passkeys — such as a synced vault passkey plus a hardware key — ensures cancelling one compromised passkey does not leave a keeper without backup recovery.)*

**T10 — Rate Exhaustion / Open Device Key Flooding (A1, A4):**
An attacker floods `/recover/begin` to bloat `recover_challenges`, or a rogue keeper/vault compromise mints endless open `device_keys` hitting `MaxOpenDeviceKeys`.
- *Mitigation:* Tight per-IP rate limiting in `PublicHandlerWithRateLimit` (`10/min`), Caddy `16KB` request-body cap, pruning expired challenge/setup rows on insert, plus a per-member recovery mint quota (**3** recovery mints in 24h) enforced before calling `s.issueKey`.

**T11 — XSS, Clickjacking, and Cache Leakage on `/recover*` (A1):**
Injected scripts or hidden iframes on `/recover` steal the minted `#k=<key>` `/join` URL from DOM or browser cache.
- *Mitigation:* Strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`, `form-action 'self'`), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `textContent`-only DOM rendering matching `core/portal/portal.js`. Note: returned JSON delivers `link` directly in response to `POST /hogman/v1/recover/finish` (never over `GET` query params).

**T12 — Total Loss of Both Mesh Devices and Passkey Vault (Operational):**
Keeper loses every device and loses access to their synced vault / all hardware keys.
- *Mitigation:* None by design (**D-12**): operator recovery is intentionally absent. Portal onboarding (`#herd` note added in PR #29) warns keepers up front to store a recovery passkey in a synced manager they can reopen from a new device.

## 6. Operational Limits & What This Does Not Cover

- **Hosted pens' `PUBLIC_HOST` names are fixed for the life of the pen:** WebAuthn binds credentials to `RPID` (`cfg.PublicHost`). Renaming `PUBLIC_HOST` silently strands every registered passkey. If a self-hosted pen ever moves to a new domain, keepers must register new passkeys under the new `PUBLIC_HOST` from `home.<zone>` before losing access.
- **Single-keeper total loss is permanent:** If a pen's sole keeper loses all devices and all passkeys, no operator tool can recover the pen without recreating control state from the server host. Pens concerned about human key loss should keep 2+ trusted keepers (`owner`/`admin`) or store passkeys in an independently recoverable vault.
- **No compromise isolation if the core host itself is breached:** Registrar holds Headscale credentials and SQLite; host compromise bypasses WebAuthn completely.

## 7. Resolved Design Decisions (From Review & Red Team)

1. **Eligible roles (`owner` + `admin`):** Recovery is available to active `owner` and `admin` keepers, and closed to regular `member` accounts.
2. **Recovered link TTL & quota:** Recovered `kind="personal"` links use a **15-minute** TTL (`RecoveryKeyTTL`), capped at **3 recovery mints per keeper per 24 hours**. Attempts refused because a cool-off or unused recovery key is already active do **not** consume the 24h retry quota.
3. **Mint-only `/recover` + 72h cool-off:** `/recover` strictly mints one replacement `/join` link; destructive device/member/passkey changes are blocked for **72 hours** on recovered devices, with immediate cancellation from pre-existing devices or co-keepers on `home.<zone>`.
4. **Synced passkeys (`BE=1`, NIST `AAL2`) enabled by default:** Allowed per D-12 alongside hardware keys (`BE=0`, `AAL3`). An optional per-pen `BE=0`-only (`AAL3`) policy toggle can be considered later if needed.

## 8. Implementation Plan (After Second-Look Sign-Off)

Only after second-look sign-off on this document:
1. Pin `github.com/go-webauthn/webauthn >= v0.18` in `core/registrar/go.mod` and verify `CGO_ENABLED=0` static builds.
2. Add `store.go` schema migration + transactional passkey cleanup on demotion/suspension/removal + `service_passkey.go` / `http_passkey.go` + 72h cool-off guards (`Actor.Device`) + full negative test suite from Section 4.2.
3. Add `/recover`, `/recover/setup`, and `/recover/assets/*` static SPA routes + Caddy routes in `core/config/edge.Caddyfile` and `deploy/hogman-host`.
4. Add the **Recovery passkeys** card, **Security events & active recoveries** banner, and **Cancel recovery** controls to `core/portal/index.html` and `core/portal/portal.js` (`#herd` / `#mine`).
5. Run full registrar unit tests + Caddy routing tests + CI e2e validation, and update `CHANGELOG.md` in the implementation PR.
