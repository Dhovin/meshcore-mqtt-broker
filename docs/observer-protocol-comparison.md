# MeshCore Observer Protocol & Authentication Comparison

This analysis compares the **five real, unmodified upstream MeshCore observer implementations** that support Ed25519 JWT authentication (`v1_{PUBLIC_KEY}`) against `meshcore-mqtt-broker` (`main` @ `1e5e5bf`).

> **Scope note:** `Andrew-a-g/meshcoretomqtt` (`75d4b2ef`, March 2025) was audited and excluded because it does not support JWT authentication (`v1_{PUBLIC_KEY}`), does not query repeater public/private keys, and publishes only to legacy 2-part topics (`meshcore/status`, `meshcore/packets`, `meshcore/raw`, `meshcore/debug`) without `origin_id`.

---

## Pinned Upstream Sources Audited

| Observer | Repository | Pinned Commit | Language / MQTT Library | Radio Interface |
| :--- | :--- | :--- | :--- | :--- |
| **agessaman** | `agessaman/meshcore-packet-capture` | `122d959f` (`main`) | Python / `paho-mqtt` (`VERSION2`) | Companion radio (TCP/Serial/BLE binary via `meshcore>=2.3.8`) |
| **Cisien** | `Cisien/meshcoretomqtt` | `9b4e022e` (`main`) | Python / `paho-mqtt` (`VERSION2`) | Repeater / RoomServer serial text CLI (`pyserial`) |
| **OffbandMesh** | `OffbandMesh/meshcore-firmware` | `8be9a020` (`firmware-base`) | C++ / ESP-IDF `esp-mqtt` | Native ESP32 Wi-Fi firmware (`src/helpers/wifi_observer/*`) |
| **openHop** | `openhop-dev/openhop_repeater` | `13eb8b2e` (`main`) | Python / `paho-mqtt` (`VERSION2` / v1 fallback) | `openhop_core` native Python repeater daemon |
| **meshcore-ha** | `meshcore-dev/meshcore-ha` | `0d5855bf` (`main`) | Python / `paho-mqtt` (`VERSION2`) | Home Assistant component over Companion/Repeater `meshcore-py` |

---

## Master Comparison Matrix

| Dimension | `agessaman` (`meshcore-packet-capture`) | `Cisien` (`meshcoretomqtt`) | `OffbandMesh` (`meshcore-firmware`) | `openHop` (`openhop_repeater`) | `meshcore-ha` (`meshcore-dev`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Username Format** | `v1_{UPPER_PUBKEY}` | `v1_{UPPER_PUBKEY}` | `v1_{UPPER_PUBKEY}` | `v1_{UPPER_PUBKEY}` | `v1_{UPPER_PUBKEY}` |
| **Fallback Auth Modes** | `username`/`password`, anon | `method = "password"` or `"none"` | `BrokerAuthType::Basic`, `None` | Static `username`/`password`, anon | `username`/`password`, anon |
| **Ed25519 Signing Path** | 1. Device (`sign_start`/`data`/`finish`)<br>2. PyNaCl expanded key<br>3. `meshcore-decoder` CLI | `ed25519_orlp.ed25519_sign` (key from `get prv.key` serial cmd) | C `lib/ed25519` via `LocalIdentity::sign` | `openhop_core` `LocalIdentity.sign` | 1. `meshcore-decoder` CLI<br>2. PyNaCl expanded key (key from `export_private_key`) |
| **Signature Hex Casing** | **lowercase** (CLI/PyNaCl/device) | **UPPERCASE** (`signature_bytes.hex().upper()`) | **UPPERCASE** (`"%02X"`) | **lowercase** (`binascii.hexlify`) | **lowercase** (PyNaCl) / CLI |
| **Default JWT TTL** | **24h** (`86400s`, `MQTTn_TOKEN_TTL`) | **1h** (`3600s`, cached `ttl - 300s`) | **`refresh_sec + 60s`** (default `3600+60s`, min `60s`) | **10m** (`600s`, `jwt_expiry_minutes=10`) | **1h** (`3600s`, min `60s`, cached `exp - 60s`) |
| **JWT Claims Emitted** | `publicKey`, `iat`, `exp`, `aud?`, `owner?`, `email?`, `client` | `publicKey`, `iat`, `exp`, `aud?`, `client`, `owner?`, `email?` | `publicKey`, `aud` (required!), `iat`, `exp`, `owner` (defaults to pubkey!), `email?` | `publicKey`, `aud` (always read), `iat`, `exp`, `email`, `owner` | `publicKey`, `iat`, `exp`, `aud?`, `owner?`, `email?`, `client` |
| **TLS PII Gating (`owner`/`email`)** | Sent whenever configured (not TLS-gated) | Only when `tls.enabled && tls.verify` | Always emits `owner` (explicit or device pubkey); `email` if set | Empty strings `email: ""`, `owner: ""` when TLS unverified | Only when `use_tls && tls_verify` |
| **Token Renewal Strategy** | Proactive (`jwt_renewal_scheduler` & pre-publish) -> `username_pw_set()` + **`reconnect()` directly** | **No timer** while connected; clears `token_cache` on disconnect and tears down + recreates client | Mid-session `esp_mqtt_set_config()` (for next reconnect); re-mints in `tryConnect()` | Proactive at `80% + 5%*idx` -> **`disconnect()` + 5s timer reconnect** (`_on_pre_connect`) | **Reactive only** on auth error `rc ∈ {4,5,134,135}` -> `_async_refresh_auth_and_reconnect()` |
| **MQTT `client_id`** | `meshcore_client_<key_or_name>` truncated **`[:23]`** (+ `_{n}` for `n>1`) | `meshcore_<pubkey>` truncated **`[:23]`** (+ `_{idx}` for `idx>0`) | `esp-mqtt` default (`ESP32_<suffix>`) | **Untruncated** `meshcore_{PUBKEY}_{host}_{format}` (~95+ chars) | `meshcore_<key_or_name>` truncated **`[:23]`** (`{prefix[:20]}_{n}[:23]`) |
| **Session `clean_session`** | `True` | `True` | `esp-mqtt` default (`clean_session=true`) | `paho` default (`True`) | `True` |
| **Transports** | `tcp`, `websockets` (+ TLS) | `tcp`, `websockets` (+ TLS) | `tcp`, `tls`, `wss` (via URI) | `websockets` (default), `tcp` (+ TLS) | `tcp`, `websockets` (+ TLS) |
| **Default WebSocket Path** | `/` (`MQTTn_WEBSOCKET_PATH`) | **Hardcoded `/`** (no config option) | From URI (default none / root) | **Paho default `/mqtt`** (no `ws_set_options` call) | `/` (`DEFAULT_MQTT_WS_PATH`, configurable) |
| **Keepalive & Pings** | **`120s` (WS)** / `60s` (TCP) | `60s` + **45s raw WebSocket `sock.ping()` thread** | **Fixed `60s`** (overridden from `esp-mqtt` `120s` default) | **`30s`** default | `60s` default |
| **Default Global IATA** | None (`MQTTn` skipped if required & unset) | **`"XXX"`** (`config.toml.example`) | `""` (skips publish if unset) | **`"TEST"`** | **`"XYZ"`** (`DEFAULT_MQTT_IATA`) |
| **Topic Prefix / Structure** | `meshcore/{IATA}/{PUBKEY}/{sub}` (custom fallback if no IATA & non-letsmesh) | `meshcore/{IATA}/{PUBKEY}/{sub}` (per-broker overrides allowed) | `{topic_prefix}/{IATA}/{PUBKEY}/{leaf}` | `letsmesh`/`waev`/`meshcoretomqtt`: `meshcore/{IATA}/{PUBKEY}/{sub}`<br>`mqtt`: `meshcore/repeater/{node_name}/{sub}` | `meshcore/{IATA}/{PUBKEY}/{sub}` (`/events -> /packets` only for `letsmesh.net`) |
| **LWT Configuration** | **Yes** (`status="offline"`, `CONNECT`-time UTC ts, `qos=0`, **`retain=True`**) | **Yes** (`status="offline"`, `CONNECT`-time UTC ts, `retain=True` default) | **None** | **None** (publishes `"offline"` explicitly in `disconnect()`) | **Yes** (`status="offline"`, `CONNECT`-time UTC ts, `qos=0`, **`retain=True`**; also publishes `"offline"` in `async_stop()`) |
| **QoS Used** | `0` (clamps `qos=1 -> 0` in `safe_publish`) | `0` in `safe_publish` (clamps `1->0`); **`1`** in `serial/responses` & connect `/status` if configured | **`0`** across all topics | `0` for `packets`/`raw`; **`1`** for `neighbors` & `status` (when `retain_status=True`) | Hardcoded **`0`** across all topics |
| **Retain Flag** | `True` on `status` & LWT; `False` on `packets`/`raw`/`neighbors` | `True` default on connect `status` & LWT; `False` in `publish_status` & `packets` | **`True` on `status` AND `neighbors`**; `False` on `packets`/`raw` | Configurable `retain_status` (default `False` on letsmesh preset) on `status` & `offline`; `False` on `neighbors` | **`True` on `status` & LWT**; `False` on `packets` |
| **Subtopics Published** | `status`, `packets`, `raw` (opt-in), `neighbors` (opt-in) | `status`, `packets`, `debug` (when `--debug`) | `status`, `packets`, `raw`, `neighbors` | `status`, `packets`, `raw`, `neighbors` | `status`, `packets` (or configured `topic_events`) |
| **Subtopics Subscribed** | None | `{global_iata}/{PUBKEY}/serial/commands` (`qos=1`) | None | None | None |
| **`origin_id` on `/packets`** | Present (`UPPER_PUBKEY`) | Present (`UPPER_PUBKEY`) | **Omitted** (`#727 sec4` slimmed JSON!) | Present (`UPPER_PUBKEY`) | Present (`UPPER_PUBKEY`) |
| **Timestamp Format** | ISO-8601 UTC (`+00:00`) | ISO-8601 UTC (`+00:00`) | **Local time without timezone** (`YYYY-MM-DDTHH:MM:SS.000000` via `localtime_r`) | ISO-8601 UTC (`+00:00`) | ISO-8601 UTC (`+00:00`) |

---

## Detailed Protocol Differences & Broker Compatibility Hazards

### 1. Authentication, Signing & Reconnect Renewal Differences

1. **Clockless / Boot-Time Behavior:**
   - **OffbandMesh** splits transports by clock sanity (`wallClockSane()`: `std::time(nullptr) > 1735689600`, i.e., `2025-01-01 UTC`): it withholds `wss://` and `tls://` connections in state `HeldNoClock` until SNTP or GPS syncs, but starts `mqtt://` (`tcp`) immediately. Because `MqttAuthJwt` mints `iat = time(nullptr)`, a clockless TCP attempt sends an un-synced `iat` (though `@michaelhart/meshcore-decoder` verifies `exp` rather than `iat` plausibility).
   - **Cisien** runs `wait_for_system_time_sync` (`timedatectl status`) at startup (up to 60s) before setting repeater RTC time and minting tokens.

2. **Token Renewal & Overlapping Session Takeover (`agessaman` vs. `openHop` vs. `meshcore-ha` vs. `Cisien` vs. `OffbandMesh`):**
   - **`agessaman`** updates credentials on the existing Paho client (`mqtt_client.username_pw_set(username, new_token)`) and calls **`mqtt_client.reconnect()` directly** without a prior `disconnect()`. When the broker (`Aedes`) receives the new TCP/WebSocket `CONNECT` with the same `client_id`, `Aedes.registerClient()` closes the *old* socket internally **without** receiving an MQTT `DISCONNECT` packet — which causes `Aedes` to fire the old socket's Last Will & Testament (`"status": "offline"`) right as the replacement session connects!
   - **`openHop`** schedules `reconnect_for_token_expiry()` at `80% + 5%*broker_index` of JWT lifetime, schedules `_attempt_reconnect()` 5s later, and calls `client.disconnect()` cleanly first (`_on_pre_connect` re-mints before reconnect). Notably, `openHop`'s default `jwt_expiry_minutes=10` means renewals occur every ~8 minutes in normal operation.
   - **`meshcore-ha`** has **no proactive JWT timer**. If its TCP/WebSocket connection drops after the 1h token TTL has elapsed, Paho auto-reconnects using the *expired cached token*, receives `CONNACK` failure (`rc=5` / `135` Not authorized), triggers `_is_auth_error()` -> `_async_refresh_auth_and_reconnect()`, mints a fresh token (`force_refresh=True`), and reconnects. Against `meshcore-mqtt-broker`, every expired-token reconnect generates at least one failed auth event in the IP `RateLimiter` (`10 failures in 60s -> 5 min IP block`); with 6 configured broker slots behind one HA instance expiring together, rapid reconnect retries risk hitting the IP block threshold.
   - **`Cisien`** has **no proactive renewal timer** while a connection stays open; it relies on Aedes not disconnecting already-authenticated sessions when JWT `exp` passes and clears `token_cache` only after a disconnect occurs.
   - **`OffbandMesh`** re-mints during `MqttBroker::loop()` (`needsRefresh`) and pushes the new credential into `esp-mqtt` via `esp_mqtt_set_config()` so the *next* disconnect/reconnect picks it up seamlessly without tearing down the live socket.

3. **Client ID Construction:**
   - **`openHop`** sends an **untruncated** `client_id` such as `meshcore_<64_HEX_PUBKEY>_<host>_letsmesh` (~95+ bytes), whereas `agessaman`, `Cisien`, and `meshcore-ha` truncate to the MQTT 3.1 `<= 23` byte limit (note: `Cisien` appends `_{idx}` after `[:23]`, yielding up to 25 bytes, and `agessaman` appends `_{n}` after `[:23]`). Brokers enforcing strict 23-byte MQTT 3.1 `clientId` limits would reject `openHop`, `Cisien` (slot > 0), and `agessaman` (slot > 1), whereas MQTT 3.1.1 / Aedes permits longer UTF-8 identifiers.

---

### 2. Transport, WebSocket Paths, Keepalive & Rate Limiter Interactions

1. **WebSocket Upgrade Path (`/` vs. `/mqtt`):**
   - **`Cisien`** hardcodes `ws_set_options(path="/", headers=None)` with no configuration knob.
   - **`agessaman`** and **`meshcore-ha`** default to `ws_path = "/"` (configurable).
   - **`openHop`** does not call `ws_set_options()`, so `paho-mqtt` sends the WebSocket HTTP upgrade to **`/mqtt`**.
   - **`OffbandMesh`** passes whatever path is present in `cfg_.url` (e.g., `/`, `/mqtt`, or `/peer`).
   - Any broker (or reverse proxy) must therefore accept MQTT WebSocket upgrades on at least `/` and `/mqtt` (and handle subpath routing cleanly).

2. **Keepalive & WebSocket Control Frames:**
   - Default MQTT keepalive spans `30s` (`openHop`), `60s` (`Cisien`, `OffbandMesh`, `meshcore-ha`, `agessaman` TCP), and **`120s`** (`agessaman` WebSockets).
   - `Cisien` additionally spawns a daemon thread (`WS-Ping-*`) sending RFC 6455 WebSocket `PING` control frames every `45s` (`sock.ping()`), which requires the broker's WebSocket server to respond with `PONG` without interfering with MQTT binary framing.

3. **Default Unconfigured IATA Codes (`XXX`, `XYZ`, `TEST`):**
   - `Cisien` defaults to `iata = "XXX"` and immediately connects + publishes `/status` + subscribes to `meshcore/XXX/{PUBKEY}/serial/commands`. On `meshcore-mqtt-broker` (`main`), `XXX` triggers immediate client disconnect (and counts toward unauthorized publish/close if misconfigured).
   - `meshcore-ha` defaults `global_iata = "XYZ"`. It explicitly disables `letsmesh.net` slots when IATA is `""` or `"XYZ"`, **but allows non-LetsMesh self-hosted `meshcore-mqtt-broker` connections with `XYZ`!** Wait: is `XYZ` a valid IATA airport code (`airport-utils`) or rejected by `src/server.ts`? We will test this live in Phase 3!
   - `openHop` defaults `iata_code = "TEST"` (uppercase `"TEST"` -> normalized by `meshcore-mqtt-broker` to `"test"` when `ALLOWED_REGIONS` is unset, but blocked under `ALLOWED_REGIONS` unless `"test"` is listed!).

---

### 3. LWT, Retain, QoS & Timestamp Differences

1. **`CONNECT`-Time LWT Timestamp vs. Stale-Status Protection:**
   - `agessaman`, `Cisien`, and `meshcore-ha` all serialize their Last Will and Testament JSON **once at `CONNECT` time**, embedding the `CONNECT`-time `timestamp`. Because `meshcore-mqtt-broker` (`src/server.ts` `aedes.authorizeForward`) tracks `lastStatusTimestamps` per `origin_id` and drops `/status` messages whose `timestamp < lastStatusTimestamps.get(origin_id)`:
     - As soon as an observer publishes *any* newer `"online"` status heartbeat (`T_online > T_connect`), a subsequent unclean disconnect causes `Aedes` to emit the stored LWT (`status="offline"`, `timestamp=T_connect < T_online`) — **which `authorizeForward` silently drops as "stale"**!

2. **Slimmed `/packets` Omitting `origin_id` (`OffbandMesh` `#727 sec4`):**
   - `OffbandMesh` `buildPacketJsonFromRecord()` explicitly drops `origin_id` (along with `packet_type`, `route`, `hash`, etc.) from `/packets` payloads to fit 3x more packets in its ring buffer:
     ```json
     {"origin":"TestNode","timestamp":"2026-11-23T08:00:00.000000","type":"PACKET","direction":"rx","raw":"...","SNR":"8.5","RSSI":"-89","score":"1000"}
     ```
   - Notice `OffbandMesh` **keeps** `origin_id` in `/status`, `/raw`, and `/neighbors`, omitting it *only* on `/packets`. On unmodified `main` (`src/server.ts` `authorizePublish` & `src/peer-bridge.ts` `validatePeerPacket`), missing `origin_id` causes publish rejection (`Error('Message must contain origin_id field')`) and client disconnect!

3. **Timezone-less Local Timestamps (`OffbandMesh` `formatIsoTimestamp`):**
   - `OffbandMesh` uses `localtime_r` + `strftime("%Y-%m-%dT%H:%M:%S")` + `".000000"` **with no `Z` or `+00:00` offset**.
   - In Node.js/V8 (`new Date(message.timestamp).getTime()`), an ISO string without a timezone offset is parsed as **local time** of the broker process (`TZ`), which works when `TZ=UTC` (Alpine container default) and observer is UTC, **but shifts forward or backward by hours** if the ESP32 device uses a local timezone (`localtime_r`) while the broker runs in UTC (or vice versa): a device east of UTC appears in the future (clamped to `+60s`, potentially blocking subsequent UTC timestamps or causing false stale drops).

4. **QoS, Retain, and Allowed Subtopics:**
   - `Cisien` subscribes to `meshcore/{global_iata}/{PUBKEY}/serial/commands` (`qos=1`) even if a specific broker overrides `broker.topics.iata`; when `global.iata` differs from the broker's allowed region, `serialize` subscribe/publish topic prefixes diverge!
   - `Cisien` publishes `DEBUG` lines to `/debug` when started with `--debug`; `meshcore-mqtt-broker` permits only `{packets, status, neighbors, raw, serial/responses}`, silently dropping `/debug` via `$drop` without disconnecting.
   - `meshcore-ha` supports configuring custom `topic_events` (e.g. `.../events`) and rewrites `/events -> /packets` **only** when `letsmesh.net` is in `server` or `audience`, meaning self-hosted `meshcore-mqtt-broker` users configuring `/events` get silently dropped packets. Additionally, in `payload_mode="raw"`, `meshcore-ha` publishes a non-standard raw-event wrapper (`{timestamp, origin, origin_id, source, event_type, payload}`) to `topic_packets`!
   - `OffbandMesh` publishes `/neighbors` with **`retain=True`** (`MqttBrokerPool.cpp`), while `openHop` and `agessaman` publish `/neighbors` with `retain=False`. (`meshcore-mqtt-broker` strips `retain` only on `/status`, leaving `/neighbors` retained.)
   - `openHop` publishes `/raw` via `publish_packet` using lowercase `"type": "raw"` + `"bytes"`, whereas `Cisien`/`OffbandMesh`/`agessaman` use uppercase `"type": "RAW"` + `"data"` (and `Cisien` omits `/raw` publishing altogether, instead embedding `"raw"` inside `/packets`).

---

## Payload Schema Comparison

### `/status` (`meshcore/{IATA}/{PUBKEY}/status`)

| Field | `agessaman` | `Cisien` | `OffbandMesh` | `openHop` | `meshcore-ha` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `status` | `"online"` / `"offline"` | `"online"` / `"offline"` | `"online"` / `"offline"` | `"online"` / `"offline"` | `"online"` / `"offline"` |
| `timestamp` | UTC ISO (`+00:00`) | UTC ISO (`+00:00`) | Local ISO (no `Z`/offset) | UTC ISO (`+00:00`) | UTC ISO (`+00:00`) |
| `origin` | `device_name` | `repeater_name` | `node_name` (or `device_id`) | `node_name` | `node_name` |
| `origin_id` | `UPPER_PUBKEY` | `UPPER_PUBKEY` | `UPPER_PUBKEY` | `UPPER_PUBKEY` | `UPPER_PUBKEY` |
| `radio` | `"freq,bw,sf,cr"` (online) | `"freq,bw,sf,cr"` | `"%.6f,%.1f,%u,%u"` | `"MHz,kHz,sf,cr"` | `"freq,bw,sf,cr"` (cached) |
| `model` | from `DEVICE_INFO` (online) | from `board` cmd | sanitized `getManufacturerName()` | `"openHop-Repeater"` | from `DEVICE_INFO` |
| `firmware_version` | from `DEVICE_INFO` (online) | from `ver` cmd | `FIRMWARE_VERSION` | `openhop_repeater` version | from `DEVICE_INFO` |
| `client_version` | `meshcore-packet-capture/...` | `meshcoretomqtt/<ver>` | `CLIENT_VERSION` | `openhop_repeater/<ver>` | `meshcore-dev/meshcore-ha:<ver>` |
| `stats` | core/radio/packets (online) | core/radio/packets (online if available) | `battery_mv`, `uptime_secs`, `errors`, `queue_len`, `noise_floor`, `tx_air_secs`, `rx_air_secs`, `recv_errors` | `uptime_secs`, `packets_sent`, `packets_received`, `errors`, `queue_len` | `uptime_secs`, `battery_mv`, `debug_flags`, `queue_len`, `noise_floor`, `tx_air_secs`, `rx_air_secs`, `recv_errors` |
| Extra fields | LWT omits `stats`/`model`/etc. | LWT omits `stats` | `repeat: "on"/"off"`, optional `lat`/`lon` | `repeat: "on"/"off"`, optional `location` | `source: "meshcore-ha"` |

### `/packets` (`meshcore/{IATA}/{PUBKEY}/packets`)

| Field | `agessaman` | `Cisien` | `OffbandMesh` (`#727 sec4`) | `openHop` | `meshcore-ha` (`mode="packet"`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `origin_id` | Yes | Yes | **NO (Omitted!)** | Yes | Yes |
| `origin`, `timestamp`, `type="PACKET"`, `direction` | Yes | Yes | Yes | Yes | Yes |
| `time`, `date`, `len`, `packet_type`, `route`, `payload_len` | Yes | Yes | **NO (Omitted!)** | Yes (varies by `openhop_core` event dict) | Yes |
| `raw` | Yes | Yes | Yes | Yes | Yes |
| `SNR`, `RSSI` | Yes (strings) | Yes (RX strings) | Yes (`"%.1f"`, `"%d"`) | Yes | Yes (strings) |
| `score` / `duration` | Neither | `score`, `duration` (RX) | `score` (when `>= 0`), no `duration` | Varies | `score`, `duration` |
| `hash` | Yes | Yes (RX) | **NO (Omitted!)** | Varies | Yes |
| `path` | RX `route=="D"` (`","` joined) | RX `route=="D"` | **NO (Omitted!)** | Varies | RX `route=="D"` |
| `decoded` | Optional (`PACKETCAPTURE_DECODE_PAYLOADS`) | No | No | No | No |
