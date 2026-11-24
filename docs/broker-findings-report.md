# MeshCore MQTT Broker Compatibility Findings Report (`main` @ `1e5e5bf`)

This report documents the live end-to-end compatibility audit of **unmodified `meshcore-mqtt-broker` (`main` @ `1e5e5bf`, v1.1.0)** against **five unmodified upstream MeshCore observer implementations** running inside Docker (`meshcore-broker-main` on `meshcore-audit-net`).

---

## 1. Audit Environment & Pinned Subjects

- **Broker Under Test:** `meshcore-mqtt-broker` v1.1.0 (`main` @ `1e5e5bf`), `Node.js v24.22.3` (`linux/x64`), `aedes v0.51.3`, `ws ^8.22.0`, `@michaelhart/meshcore-decoder ^0.3.0`, `airport-utils ^1.5.5`.
- **Broker Configuration:** `LOG_LEVEL=debug`, `MQTT_WS_PORT=8883`, `ENABLE_TCP_MQTT=true`, `MQTT_TCP_PORT=1883`, `AUTH_EXPECTED_AUDIENCE=audit.meshcore.local`, `ALLOWED_REGIONS=""`, `MQTT_SYS_INTERVAL_MS=2000`, `SUBSCRIBER_1` (Role 1 Admin), `SUBSCRIBER_2` (Role 3 Limited).
- **TLS Proxy:** Local CA + SAN cert (`DNS:localhost,IP:127.0.0.1`) terminating `wss://127.0.0.1:8443 -> meshcore-broker-main:8883` and `mqtts://127.0.0.1:8444 -> meshcore-broker-main:1883`.
- **Verified Clean Upstream Observer Checkouts (`git status --porcelain` empty on all 5):**
  1. **agessaman** (`agessaman/meshcore-packet-capture`): `122d959f047cb1750218abfadbab7e05bc6c9ba2`
  2. **Cisien** (`Cisien/meshcoretomqtt`): `9b4e022e298020ef3359b36d8c364931de058af5`
  3. **OffbandMesh** (`OffbandMesh/meshcore-firmware`): `8be9a02003cfae4427cb349606938fa4fd2869bc`
  4. **openHop** (`openhop-dev/openhop_repeater` + `openhop_core==1.1.3`): `13eb8b2ea8b1cdb4a07ed6e282dc99e3aa8a5a8b`
  5. **meshcore-ha** (`meshcore-dev/meshcore-ha`): `0d5855bfe5b1802fce0857e175674700179c33f1`

> **Exclusion note:** `Andrew-a-g/meshcoretomqtt` (`75d4b2ef`) was audited and excluded prior to harness execution because it lacks JWT authentication (`v1_{PUBLIC_KEY}`).

---

## 2. Test Run Summary (19 Scenarios)

**Totals:** `11 PASS`, `4 FAIL` (genuine broker compatibility/correctness bugs), `4 EXPECTED_QUIRK`, `0 SKIPPED`.

| Scenario ID | Observer | Result | Key Observation |
| :--- | :--- | :--- | :--- |
| `agessaman_1a_baseline_wss` | agessaman | **PASS** | `wss://` on `/`, `status` retain stripped (`false`), `packets` + `raw` delivered, `/internal` Role-1 only, Role-3 fields stripped (`stats`/`model`/`firmware_version`, `SNR`/`RSSI`/`score`). |
| `agessaman_1b_neighbors_now` | agessaman | **PASS** | `--neighbors-now --neighbors-exit` published `/neighbors` (`421 B`, `retain: false`). |
| `agessaman_1c_proactive_jwt_renewal` | agessaman | **PASS\*** | Proactive `username_pw_set` + `reconnect()` succeeded and post-renewal `/packets` arrived, **\*but broker logs prove Aedes fired the old client's LWT on takeover, only masked by Finding #2**. |
| `agessaman_1d_unclean_kill_lwt` | agessaman | **FAIL** | After `"online"` status (`23:29:19.958Z`), `SIGKILL` triggered LWT (`23:29:18.911Z`) which **`authorizeForward` blocked as stale** (`offline_lwt_delivered: false`). |
| `cisien_2a_baseline_wss_and_debug` | Cisien | **PASS** | Uppercase-hex Ed25519 JWT auth succeeded, `/packets` delivered, Role-3 fields stripped, `--debug` `/debug` silently dropped without disconnecting session. |
| `cisien_2b_remote_serial` | Cisien | **PASS** | Admin-signed `ver` command on `/serial/commands` executed over PTY and returned 3-part JWT on `/serial/responses` (hidden from Role 3). |
| `cisien_2c_unclean_kill_lwt` | Cisien | **FAIL** | After `"online"` status (`23:29:33.150Z`), `SIGKILL` triggered LWT (`23:29:33.106Z`) — 44 ms earlier — which **`authorizeForward` blocked as stale**. |
| `cisien_2d_default_xxx_iata` | Cisien | **EXPECTED_QUIRK** | Observer killed during 2.5s serial init before MQTT connect (`XXX` explicit rejection verified in `src/server.ts:824-831` and mirrored by `ha_5d` below). |
| `offband_3a_slim_packets_wss` | OffbandMesh | **FAIL** | Slimmed `/packets` (`#727 sec4`, omits `origin_id`) denied with `Error: Message must contain origin_id field`; **broker kicked client before `/raw` or `/neighbors` could flush**. |
| `offband_3b_multi_transport_and_neighbors_retain` | OffbandMesh | **PASS** | With `--no-slim-packet`, `/status`, `/raw`, `/neighbors` succeeded over `wss://`, `mqtts://`, `mqtt://`. Probe confirmed **`status_persisted_retained: false`**, **`neighbors_persisted_retained: true`**. |
| `offband_3c_non_utc_timezone` | OffbandMesh | **EXPECTED_QUIRK** | With `TZ=Asia/Tokyo`, `/status` carried zoneless local timestamp `2026-11-24T08:29:52.000000` (`has_timezone_suffix: false`). |
| `openhop_4a_baseline_ws_and_jwt_renew` | openHop | **PASS** | `wss://.../mqtt`, 92-char `client_id`, `status`/`packets`/`raw`/`neighbors` all delivered, proactive `disconnect()` + 5s reconnect JWT renewal succeeded, clean `"offline"` delivered. |
| `openhop_4b_default_test_iata` | openHop | **PASS** | Default `TEST` region normalized cleanly to `meshcore/test/{PUBKEY}/...` when `ALLOWED_REGIONS` is unset. |
| `ha_5a_baseline_wss` | meshcore-ha | **PASS** | Baseline `wss://` on `/`, `source: "meshcore-ha"`, `packets`, clean `async_stop()` `"offline"` all delivered. |
| `ha_5b_abrupt_lwt` | meshcore-ha | **FAIL** | After `"online"` status (`23:30:01.478Z`), abrupt socket drop triggered LWT (`23:30:01.465Z`) — 13 ms earlier — which **`authorizeForward` blocked as stale**. |
| `ha_5c_custom_events_topic` | meshcore-ha | **EXPECTED_QUIRK** | Custom `/events` subtopic on non-LetsMesh server silently dropped by broker allowlist without disconnecting session. |
| `ha_5d_default_xyz_iata` | meshcore-ha | **EXPECTED_QUIRK** | Non-LetsMesh `XYZ` triggered immediate `[DISCONNECT] Closing client - Invalid IATA code: "XYZ"`, duplicate LWT denial, and 9 reconnect loops in ~0.4s (plus `MASK must be set` WS frame errors). |
| `ha_5e_reactive_jwt_renewal` | meshcore-ha | **PASS** | After 63s (`ttl=60`), expired JWT reconnect failed (`auth_failures_delta: 1`, 2 unauthenticated WS closes), triggering `_async_refresh_auth_and_reconnect()` recovery. |
| `neg_6_wrong_audience_auth` | OffbandMesh | **PASS** | Mismatched JWT `aud` (`wrong.invalid.example`) cleanly rejected during `CONNECT` (`connected: false`, `error_class: 1`). |

---

## 3. Prioritized Broker Findings & Root Causes

### Finding 1 [CRITICAL] — OffbandMesh `#727 sec4` Slim `/packets` Payload Rejected (`missing origin_id`) & Disconnects Client
- **Live Evidence (`offband_3a_slim_packets_wss`, `broker_main.log` lines 191–206):**
  ```text
  [O:C58C3039] [AUTHZ] ✓ Publish authorized -> meshcore/SEA/C58C3039.../status
  [O:C58C3039] [PUBLISH] meshcore/SEA/C58C3039.../status (446 bytes)
  [O:C58C3039] [AUTHZ] ✗ Publish denied -> meshcore/SEA/C58C3039.../packets (missing origin_id)
  [O:C58C3039] [ERROR] Client error: Message must contain origin_id field
  [O:C58C3039] [CLIENT] Disconnected (connected for 0s)
  [O:C58C3039] [WEBSOCKET] Connection closed from 172.18.0.3 - Code: 1001, Reason: none
  ```
- **Root Cause:**
  1. Unmodified `OffbandMesh` firmware (`MqttPayload::buildPacketJsonFromRecord()`) deliberately omits `origin_id` on the `/packets` subtopic (while still including `origin_id` on `/status`, `/raw`, and `/neighbors`).
  2. In [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L975-L994), `aedes.authorizePublish` unconditionally rejects any JSON payload missing `message.origin_id` with `callback(new Error('Message must contain origin_id field'))`. Passing an `Error` to Aedes `authorizePublish` emits `clientError` and **forcibly disconnects the publisher socket**, losing all `/packets` telemetry and terminating queued `/raw` and `/neighbors` publishes.
  3. **Peer-bridge coupling ([src/peer-bridge.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/peer-bridge.ts#L160-L167)):** Even if Broker A accepted slim `/packets`, `validatePeerPacket()` on receiving Peer Broker B independently enforces `message.origin_id` (`64-hex` matching topic pubkey), so Peer Broker B would drop every forwarded OffbandMesh `/packets` message unless `origin_id` is either injected by Broker A when missing on `/packets` or made optional when validated against the authenticated topic pubkey on `/packets` in `validatePeerPacket()`.
- **Proposed Fix (Phase 4):**
  - On `/packets` when `message.origin_id` is omitted (`undefined`/`""`) for an authenticated publisher (`src/server.ts`), accept the packet using the authenticated topic public key (`clientPublicKey`) — which has already been verified against the MQTT username & JWT — or reject only if `origin_id` is *present* and mismatches `clientPublicKey`.
  - To keep downstream Role 1/2/3 subscribers and Peer Brokers (`src/peer-bridge.ts:160-167`) 100% compatible without breaking Peer B or downstream JSON consumers expecting `origin_id`, either inject `origin_id: clientPublicKey` onto `/packets` when missing (or also allow omitted `origin_id` on `/packets` in `validatePeerPacket()` for peer-to-peer robustness).

---

### Finding 2 [CRITICAL] — Stale-Status Filter Silently Drops Legitimate `CONNECT`-Time LWT `"offline"` Messages
- **Live Evidence (`agessaman_1d`, `cisien_2c`, `ha_5b`, plus `agessaman_1c` & `ha_5e`, `broker_main.log` lines 119–121, 153–155, 188–190, 395–397, 595–597):**
  ```text
  # agessaman_1d (1.047s gap -> DROPPED)
  [FILTER] Blocking stale status message for 85DD5502 (2026-11-23T23:29:18.911Z < 2026-11-23T23:29:19.958Z)
  # cisien_2c (44ms gap -> DROPPED)
  [FILTER] Blocking stale status message for 9AF34C0C (2026-11-23T23:29:33.106Z < 2026-11-23T23:29:33.150Z)
  # ha_5b (13ms gap -> DROPPED)
  [FILTER] Blocking stale status message for 8AB1133E (2026-11-23T23:30:01.465Z < 2026-11-23T23:30:01.478Z)
  # ha_5e (14ms gap -> DROPPED)
  [FILTER] Blocking stale status message for A56BE869 (2026-11-23T23:30:17.717Z < 2026-11-23T23:30:17.731Z)
  ```
- **Root Cause:**
  - `agessaman`, `Cisien`, and `meshcore-ha` all serialize their static MQTT Last Will & Testament (`{"status":"offline","timestamp":...}`) **once at `CONNECT` time**, then publish `"online"` in `on_connect` 10–1000 ms later (and subsequent periodic/stats heartbeats advance `lastStatusTimestamps` even further).
  - In [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1183-L1207), `aedes.authorizeForward` drops any `/status` message whose `timestamp < lastStatusTimestamps.get(originId)`. Every unclean disconnect (`SIGKILL`, power sag, WAN drop) fires the static `CONNECT`-time LWT, whose timestamp is always older than the session's last `"online"` message — causing **100% of unclean `"offline"` LWTs to be silently discarded**. (Notice also the duplicate `[FILTER]` log line per LWT because `authorizeForward` runs once per matched subscriber — `audit_admin` and `audit_limited`!)
- **Proposed Fix (Phase 4 — MUST land together with Finding 3):**
  - Tag genuine Aedes Last Will publishes in `authorizePublish` (`packet === (client as any).will`, e.g., attaching a non-enumerable or internal symbol/property `(packet as any)._isLwt = true` or rewriting stale LWT `timestamp` when `status === 'offline'`, carefully avoiding re-poisoning by reconnect races!).
  - Better design: Track active/latest connection epoch or handle LWT in `authorizePublish` / `authorizeForward`: when `packet === (client as any).will` (and no *newer* `"online"` status from a **different/newer connection** has arrived since the disconnect began — noting that on session takeover we fix Finding 3 via `suppressWill`), allow the terminating session's legitimate LWT through (and stamp `timestamp` to `Math.max(lwtTs, lastTimestamp)` or `Date.now()` / track per-session LWT validity) while **still** blocking stale `"online"`/`"offline"` messages from peer queues or duplicate slow paths!

---

### Finding 3 [HIGH] — Proactive JWT Renewal Session Takeover (`agessaman` `reconnect()`) Triggers Old Socket's LWT in Aedes
- **Live Evidence (`agessaman_1c_proactive_jwt_renewal`, `broker_main.log` lines 111–125):**
  ```text
  110: [O:31F58AA1] [PUBLISH] .../status (658 bytes)                 <-- stats/online @ 23:29:13.349Z
  111: [WEBSOCKET] New WebSocket connection from 172.18.0.3          <-- agessaman calls reconnect() with new JWT
  112: [O:31F58AA1] [WEBSOCKET] Connection closed ... Code: 1006
  114: [O:31F58AA1] [AUTHZ] Stripping retain flag from STATUS ...    <-- Aedes fires OLD socket's LWT!
  116: [O:31F58AA1] [CLIENT] Disconnected (connected for 6s)
  119: [FILTER] Blocking stale status message for 31F58AA1 (2026-11-23T23:29:07.293Z < 2026-11-23T23:29:13.349Z)
  121: [O:31F58AA1] [PUBLISH] .../status (180 bytes)
  122: [C:meshcore_client_31F58AA] [AUTH] Authentication attempt ... <-- replacement session authenticates
  125: [O:31F58AA1] [CLIENT] Connected (IP: 172.18.0.3)
  ```
- **Root Cause:**
  - `agessaman/meshcore-packet-capture` renews its JWT in-place by calling `username_pw_set(username, new_jwt)` followed directly by **`reconnect()` without sending an MQTT `DISCONNECT`**.
  - When the replacement TCP/WebSocket connection sends `CONNECT` with the same `client_id` (`meshcore_client_<prefix>`), Aedes detects the duplicate `client.id` during client registration and destroys the old client without seeing `DISCONNECT`, which causes Aedes to **publish the old client's LWT `"offline"` right as the replacement connection comes online**.
  - On unmodified `main`, this false `"offline"` spike was *only accidentally hidden* from subscribers because Finding #2 dropped the older `CONNECT`-time LWT timestamp! Fixing Finding #2 in isolation would immediately break `agessaman` JWT renewals by emitting spurious `"offline"` statuses every renewal cycle.
- **Proposed Fix (Phase 4):**
  - On `aedes.authenticate` / `aedes.on('client', ...)` when an authenticated client (`ClientType.PUBLISHER` / matching `(client as any).publicKey`) connects with an existing active client sharing the same `client.id` (Aedes `aedes.clients[client.id]`), **or** when registering a new session for an already-connected `client.id` in Aedes, call `suppressWill(existingClient)` cleanly *before* Aedes tears down the displaced client (or buffer/cancel any in-flight will from the displaced client). Must be verified so an *unauthenticated* hijacker guessing `client.id` cannot suppress a legitimate client's will!

---

### Finding 4 [MEDIUM] — Unsuppressed LWT on Invalid IATA (`XXX`/`XYZ`) / Format Denials Causes Duplicate Errors, Double Metrics & Reconnect Storms
- **Live Evidence (`ha_5d_default_xyz_iata`, `broker_main.log` lines 417–569):**
  ```text
  [O:B4562439] [AUTHZ] Stripping retain flag from STATUS message -> meshcore/XYZ/.../status
  [O:B4562439] [AUTHZ] ✗ Publish denied -> meshcore/XYZ/.../status (invalid IATA)
  [O:B4562439] [DISCONNECT] Closing client - Invalid IATA code: "XYZ"
  [O:B4562439] [AUTHZ] Stripping retain flag from STATUS message -> meshcore/XYZ/.../status   <-- duplicate LWT!
  [O:B4562439] [AUTHZ] ✗ Publish denied -> meshcore/XYZ/.../status (invalid IATA)             <-- double count!
  [O:B4562439] [DISCONNECT] Closing client - Invalid IATA code: "XYZ"
  ... (repeated 9 times in ~0.4s) ...
  [WEBSOCKET] Error from 172.18.0.3: Invalid WebSocket frame: MASK must be set
  ```
- **Root Cause:**
  - In [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L852-L855) and [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L908), `suppressWill(client)` is called on unapproved-IATA disconnection **only when `ALLOWED_REGIONS` is configured** (`if (ALLOWED_REGIONS && ...)`), and is **omitted completely** on:
    - placeholder `XXX` rejection ([line 824](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L824-L831)),
    - invalid IATA format ([line 838](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L838-L845)),
    - invalid IATA code when `ALLOWED_REGIONS` is unset ([line 848](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L848-L860)),
    - invalid pubkey format / pubkey mismatch ([lines 867–885](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L867-L885)).
  - Calling `client.close()` without `suppressWill(client)` causes Aedes to immediately run `authorizePublish` a second time for the client's LWT on the same bad topic — doubling `unauthorized_publishes` metrics, error logs, and `client.close()` calls.
  - Because `AUTH` succeeds (`CONNACK 0`), `meshcore-ha` (when misconfigured with default `XYZ` against a non-LetsMesh broker) immediately reconnects in a tight sub-100 ms loop (9 cycles in ~0.4 s) — and overlapping server `ws.close()` vs client send/reconnect coincides with `[WEBSOCKET] Error: Invalid WebSocket frame: MASK must be set` on 9 occasions in `ha_5d` (lines 420, 442, 453, 483, 494, 507, 519, 530, 552).
- **Proposed Fix (Phase 4):**
  - Call `suppressWill(client)` on **all** server-initiated `client.close()` error paths (`XXX`, invalid IATA format, invalid IATA code regardless of `ALLOWED_REGIONS`, invalid topic pubkey, pubkey mismatch) whenever `packet !== (client as any).will`, and short-circuit `if (packet === (client as any).will)` cleanly without double-counting or double-closing.
  - Consider issuing a temporary observer-key cooldown (similar to `observerRegionBlocklist`) on repeated `XXX`/`XYZ` placeholder/invalid-IATA closes when `ALLOWED_REGIONS` is unset so misconfigured observers are throttled via `CONNACK` backoff rather than tight loops.

---

### Finding 5 [MEDIUM] — Expired JWT Logs Misleading `"Invalid token signature"` & Triggers Multiple `RateLimiter` Hits on Reactive Refresh
- **Live Evidence (`ha_5e_reactive_jwt_renewal`, `broker_main.log` lines 600–609 & `audit_results.json` lines 389–391):**
  ```text
  [C:meshcore_A56BE869AF4B25] [AUTH] Authentication attempt - Username: v1_A56BE869...
  [C:meshcore_A56BE869AF4B25] [AUTH] ✗ Invalid token signature for public key: A56BE869...
  [C:meshcore_A56BE869AF4B25] [ERROR] Client error: not authorized
  [C:meshcore_A56BE869AF4B25] [WEBSOCKET] Connection closed (unauthenticated) from 172.18.0.3 - Code: 1006, Reason: none
  [WEBSOCKET] New WebSocket connection from 172.18.0.3
  [C:null] [WEBSOCKET] Connection closed (unauthenticated) from 172.18.0.3 - Code: 1006, Reason: none
  ```
- **Root Cause:**
  - `meshcore-ha` has no proactive JWT renewal timer: after TTL expiry (`63s` in `ha_5e`), Paho auto-reconnects using the expired cached JWT, hits broker refusal, and only then generates a fresh JWT (`auth_failures_delta: 1` per expiring slot).
  - In [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L543-L550), `verifyAuthToken(passwordStr, publicKey)` returns `null` for **both** bad cryptographic signatures **and** expired `exp` claims, so the broker always logs `"Invalid token signature"` — misleading operators debugging expired clocks/tokens (especially relevant for OffbandMesh embedded RTCs or HA reactive renewals).
  - Additionally, Paho's reactive reconnect abort opened a second short-lived WebSocket (`C:null`, lines 605–607), recording **two** `rateLimiter.recordFailure(clientIP)` strikes against the 10-per-minute IP ban threshold for a single expired-token recovery (if a Home Assistant user configures 5–6 brokers expiring together, `5 × 2 = 10` unauthenticated closes can temporarily IP-ban the entire HA host!).
- **Proposed Fix (Phase 4):**
  - Decode the JWT payload `exp` / `nbf` in `src/server.ts` when `verifyAuthToken` returns `null` (verify signature first or inspect `exp` safely on a 3-part base64url JWT) so logs distinguish `Expired token (exp: ...)` from `Invalid token signature`.
  - Document / optionally tune `RateLimiter` handling so already-known / previously authenticated keys or TCP/WS handshakes closed before MQTT `CONNECT` don't cause premature IP bans during multi-broker HA restarts, or keep IP rate-limiting bounded strictly to failed auth attempts.

---

### Finding 6 [MEDIUM/LOW] — `/neighbors` Retain Flag Persisted (`OffbandMesh`) & Zoneless Local Timestamps (`OffbandMesh`)
- **Live Evidence (`offband_3b_multi_transport_and_neighbors_retain` & `offband_3c_non_utc_timezone`):**
  - `offband_3b` `retain_probe` (`audit_results.json` lines 234–235):
    - `"status_persisted_retained": false` (`src/server.ts:645-650` strips `retain` on `/status`)
    - `"neighbors_persisted_retained": true` (`OffbandMesh` sends `retain=true` on `/neighbors`, and the broker stores it as a retained MQTT message — even though `agessaman` and `openHop` publish `/neighbors` with `retain=false`!). Notice in `openHop`'s `MqttHandler` (`publish_status`) vs `OffbandMesh`'s `MqttBrokerPool.cpp`, retained `/neighbors` means new subscribers immediately receive arbitrarily old neighbor snapshots on subscribe (plus unbounded Aedes persistence growth across thousands of nodes).
  - `offband_3c` (`audit_results.json` lines 260–264):
    - Under `TZ=Asia/Tokyo`, unmodified `OffbandMesh` `buildStatusJson` emitted `"2026-11-24T08:29:52.000000"` (`has_timezone_suffix: false`), 9 hours ahead of UTC `23:29:52Z`.
    - In [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1187-L1199), `new Date(message.timestamp).getTime()` parses a timezone-less ISO timestamp in the **broker's local `TZ`**. If the broker runs in `UTC` (default Alpine container) and an ESP32 compiles/configures a non-UTC timezone (e.g. `JST`, `EST`, `PST`), eastern offsets clamp to `now + 60_000` (`lastStatusTimestamps` becomes `now + 60s`, blocking UTC statuses or future LWTs for 60s), while western offsets appear 5–8 hours *in the past* and can be silently dropped as stale behind a recent heartbeat or Peer-forwarded status!
- **Proposed Fix (Phase 4):**
  - Strip `retain = false` on `/neighbors` in `authorizePublish` ([src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L645-L650)) — or make allowed retained subtopics explicit (strip `retain` on *all* publisher subtopics, since `ALLOWED_PUBLISHER_SUBTOPICS` are time-series streams `/status`, `/packets`, `/raw`, `/neighbors`, `/serial/responses`, matching the README's ingestor-restart rationale).
  - In `authorizeForward`'s status timestamp comparison, detect timezone-less timestamps (`/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/`) from `OffbandMesh` and either normalize plausibly against broker receive time (`Date.now()`) or avoid letting a skewed zoneless clock poison `lastStatusTimestamps` by `+60s`.

---

### Finding 7 [LOW] — Minor Protocol & Authorization Cleanups
1. **Redundant `ws.pong(data)` handler ([src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1432-L1437)):**
   - The `ws` package (`v8.22.0`) enables `autoPong: true` by default on `WebSocketServer`, automatically queuing a WebSocket `PONG` frame on receipt of every client `PING` (used every 45s by `Cisien` `WS-Ping-*`). Calling `ws.pong(data)` manually in `ws.on('ping')` works today (`cisien_2a` passed cleanly), but sends a **second redundant `PONG` frame** per client `PING`. Removing the manual `ws.pong(data)` call (or keeping only the debug log) avoids duplicate control frames on the wire.
2. **`authorizeSubscribe` omits `XXX`/format check for `serial/commands` when `ALLOWED_REGIONS` is unset ([src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1098-L1122)):**
   - `authorizeSubscribe` checks `isRegionAllowed(iata, ALLOWED_REGIONS)` (which permits anything when `ALLOWED_REGIONS` is `null`), without rejecting placeholder `XXX` or non-3-letter IATAs like `authorizePublish` does — allowing `Cisien` with default `XXX` to authorize its `/serial/commands` subscription while simultaneously disconnecting on `/status`.

---

## 4. Verified Non-Bug Observer Quirks & Confirmed Working Behaviors

- **`openHop` 92-character untruncated `client_id` (`openhop_4a`):** Accepted cleanly over `wss://.../mqtt` (`meshcore_{64HEX}_127.0.0.1_letsmesh`, 92 chars); proactive `disconnect()` + 5s reconnect JWT renewal worked with zero spurious LWTs.
- **`openHop` default `TEST` IATA (`openhop_4b`):** Normalized cleanly to lowercase `meshcore/test/{PUBKEY}/...` when `ALLOWED_REGIONS` is unset.
- **`Cisien` `--debug` `/debug` subtopic (`cisien_2a`):** Broker silently drops `/debug` (`✗ Publish dropped -> .../debug (disallowed subtopic: debug)`) via `$drop` without terminating the session; subsequent `/packets` and `/serial/commands` continue normally.
- **`Cisien` remote serial (`cisien_2b`):** Admin-only `/serial/commands` -> `/serial/responses` round-trip works end-to-end; Role 3 subscribers never receive `/serial/*` or `/internal` or `$SYS/*`.
- **`meshcore-ha` custom `topic_events` (`ha_5c`):** Only rewrites `/events` -> `/packets` upstream when `letsmesh.net` is in hostname/audience; broker safely drops `/events` via `$drop` without disconnecting.
- **Multi-transport (`offband_3b`):** `wss://`, `mqtts://`, and plain `mqtt://` (`ENABLE_TCP_MQTT=true`) all connect, authenticate with Ed25519 JWTs, and deliver telemetry reliably.
- **Security boundaries (`agessaman_1a`, `cisien_2a`, `neg_6`):** Role-3 field filtering (`stats`, `model`, `firmware_version`, `SNR`, `RSSI`, `score`) and topic isolation (`/internal`, `/serial/*`, `$SYS/*`) plus mismatched-audience JWT rejection all passed as designed.

---

## 5. Summary of Recommended Phase 4 Broker Fixes (Awaiting Approval)

| Priority | Change Target | Proposed Fix |
| :--- | :--- | :--- |
| **P0** | [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L975-L994) & [src/peer-bridge.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/peer-bridge.ts#L160-L167) | Support `OffbandMesh` `#727 sec4` slim `/packets` (missing `origin_id`): accept on `/packets` and normalize/populate `origin_id` from verified topic public key (or allow omitted `origin_id` on `/packets` in `validatePeerPacket`), while still rejecting mismatched `origin_id` or missing `origin_id` on other JSON subtopics. |
| **P0** | [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1183-L1207) | Fix legitimate `CONNECT`-time LWT `"offline"` drops (`agessaman`, `Cisien`, `meshcore-ha`) in `authorizeForward` by flagging active-session LWTs (`packet === (client as any).will`) in `authorizePublish` and permitting terminating LWT delivery without breaking peer/stale-timestamp protection. |
| **P0** | [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L594-L610) / client registration | Suppress old client's LWT (`suppressWill(existing)`) on authenticated same-`client.id` session takeover (e.g., `agessaman` `reconnect()` JWT renewal) — required alongside P0 #2 to prevent false `"offline"` flickers on token refresh. |
| **P1** | [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L824-L885) & [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1098-L1122) | Call `suppressWill(client)` uniformly before all server-initiated `client.close()` disconnects (including `XXX`/invalid IATA/pubkey mismatch when `ALLOWED_REGIONS` is unset), validate IATA on `/serial/commands` subscribe, and optionally rate-limit/block repeated `XXX`/`XYZ` disconnect loops. |
| **P1** | [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L645-L650) | Strip `retain = false` on `/neighbors` (and all publisher telemetry subtopics) so `OffbandMesh`'s `retain=true` `/neighbors` publish does not persist stale snapshots in Aedes. |
| **P2** | [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L543-L550), [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1187-L1199), [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts#L1432-L1437) | Distinguish expired JWTs vs bad signatures in `[AUTH]` logs; guard `authorizeForward` against zoneless `localtime_r` timestamps from `OffbandMesh` biasing `lastStatusTimestamps`; remove redundant manual `ws.pong(data)` call. |

---

## 6. Phase 4 Fixes & Re-Verification Results

All P0, P1, and P2 fixes above have been implemented on `feature/observer-simulator` and verified against both the automated Node test suite (`node:24-alpine`) and a clean rebuild of the 5-observer live Docker audit (`meshcore-broker:phase4-audit`).

### Code Changes
- [src/config.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/config.ts): Added optional `MQTT_LWT_GRACE_MS` configuration (`lwtGraceMs`, default `1000` ms) to `loadMqttConfig()`.
- [src/peer-bridge.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/peer-bridge.ts): Updated `validatePeerPacket()` to enforce plain-object JSON payloads and permit omitted/empty `origin_id` on `/packets` (deriving `originId` from `topicPublicKey`), while preserving strict 64-hex `origin_id` + mismatch rejection elsewhere.
- [src/server.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/src/server.ts):
  - **P0 — Slim `/packets` support:** Populates missing/empty `origin_id` from verified `clientPublicKey` on `/packets` inside `aedes.authorizePublish` (rejecting mismatches and checking enriched size against `maxPacketBytes`).
  - **P0 — Deferred LWT & stale-timestamp refresh + takeover suppression:** Tracks active publisher connections (`activePublishersByKey`) and pending terminating LWTs (`pendingPublisherWills`), suppresses displaced same-key wills on authenticated session takeover in `aedes.authenticate`, cancels pending LWTs on rapid reconnect (`MQTT_LWT_GRACE_MS`), and advances stale `CONNECT`-time LWT timestamps to `lastStatusTimestamps` (`refreshLwtPayloadIfStale`) when the grace timer fires.
  - **P1 — Retain stripping & uniform will suppression:** Strips `retain = false` across all `ClientType.PUBLISHER` and `ClientType.PEER` publishes (including `/neighbors`), leaves `ClientType.SUBSCRIBER` intact, calls `suppressWill(client)` uniformly via `denyAndClosePublisher()` across all publisher close paths (`XXX`, invalid format/IATA including `XYZ` when `ALLOWED_REGIONS` is unset, invalid/mismatched pubkey, unapproved region), and validates `/serial/commands` IATA on `authorizeSubscribe`.
  - **P2 — Expired JWT clarity, zoneless timestamps, single WebSocket PONG:** Uses `decodeAuthTokenPayload` in `aedes.authenticate` to distinguish expired vs malformed vs mismatched-key vs bad-signature tokens; normalizes uppercase `originId` and 15-minute-granularity `localtime_r` offsets in `parseStatusTimestampMs()` inside `authorizeForward`; removes the duplicate manual `ws.pong(data)` frame (`ws` v8 `autoPong` already replies).
- [test/observer-compat.test.ts](file:///c:/Users/dhovi/Github/meshcore-mqtt-broker/test/observer-compat.test.ts): Added 1 unit test + 5 end-to-end regression tests covering slim `/packets`, slow-clock unclean LWTs, takeover + rapid-reconnect LWT suppression + unauthenticated hijack rejection, `XYZ`/`XXX` blocking and `/serial/commands` IATA checks, `/neighbors` retain stripping, expired JWT logging, `UTC+9`/`UTC-8` zoneless timestamps, and single WebSocket PONG per PING.

### Verification Results
- **Unit & Integration Suite (`npm test` inside `node:24-alpine`):**
  - TypeScript build (`tsc`) clean with zero errors.
  - **46/46 tests passed across 17 suites** (`fail: 0`, `cancelled: 0`, `skipped: 0`), covering `observer-compat`, `peer-forwarding`, `peer-jwt-interconnect`, `peer-multi-topology`, `region-filtering`, `scale-200-observers`, and `security`.
- **Live 19-Scenario 5-Observer Docker Audit (Before vs. After):**
  - **Before (`main` @ `1e5e5bf`):** `11 PASS`, **`4 FAIL`**, `4 EXPECTED_QUIRK`, `0 SKIPPED`
  - **After (Phase 4 build):** **`15 PASS`**, **`0 FAIL`**, `4 EXPECTED_QUIRK`, `0 SKIPPED`
  - **Previously failing scenarios now `PASS`:**
    - `offband_3a_slim_packets_wss`: **`PASS`** (`stayed_up_after_publishes: true`, `slim_packets_received: true`, `raw_received: true`, `neighbors_received: true`; log: `Populated missing origin_id on /packets from authenticated pubkey`).
    - `agessaman_1d_unclean_kill_lwt`: **`PASS`** (`online_timestamp: 2026-11-24T01:36:40.110415+00:00` -> `offline_timestamp: 2026-11-24T01:36:40.110Z`, `offline_lwt_delivered: true`).
    - `cisien_2c_unclean_kill_lwt`: **`PASS`** (`online_timestamp: 2026-11-24T01:36:49.320237+00:00` -> `offline_timestamp: 2026-11-24T01:36:49.320Z`, `offline_lwt_delivered: true`).
    - `ha_5b_abrupt_lwt`: **`PASS`** (`online_timestamp: 2026-11-24T01:37:08.954636+00:00` -> `offline_timestamp: 2026-11-24T01:37:08.954Z`, `offline_lwt_delivered: true`).
  - **Additional verified improvements in audit logs:**
    - `agessaman_1c_proactive_jwt_renewal`: **`PASS`** (`[LWT] Deferred LWT publish for 1000ms` -> `[LWT] Cancelled pending LWT (reconnected within 4ms)`, `spurious_offline_lwt_during_reconnect: false`).
    - `offband_3b_multi_transport_and_neighbors_retain`: **`PASS`** (`status_persisted_retained: false`, `neighbors_persisted_retained: false` across `wss`, `tls`, and `tcp`).
    - `ha_5d_default_xyz_iata`: **`EXPECTED_QUIRK`** with single invalid-IATA publish denial (no duplicate LWT denial) and immediate `observerRegionBlocklist` cooldown on subsequent reconnects.
    - `ha_5e_reactive_jwt_renewal`: **`PASS`** (`[AUTH] ✗ Expired auth token for public key: 2C25FF9C... (expired 4s ago, exp: 2026-11-24T01:38:27.000Z)`).
