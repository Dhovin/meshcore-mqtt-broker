# meshcore-mqtt-broker

A WebSocket-based MQTT broker with MeshCore Ed25519 public key authentication, role-based subscribers, remote serial command routing, abuse detection & trust telemetry, connection rate limiting, retained `$SYS/broker/#` operational metrics, and optional standard TCP MQTT support.

[![Build and Push Docker Image](https://github.com/Dhovin/meshcore-mqtt-broker/actions/workflows/docker-build.yml/badge.svg)](https://github.com/Dhovin/meshcore-mqtt-broker/actions/workflows/docker-build.yml)

## Features

- **WebSocket MQTT**: Fast, reliable MQTT over WebSockets on port `8883` (with 1 MB frame limit, streaming MQTT packet size validation, and bidirectional duplex backpressure)
- **Optional TCP MQTT**: Standard raw MQTT on port `1883` for Mosquitto bridges or internal forwarders
- **Public Key Authentication**: Ed25519 JWT authentication for publishers using MeshCore public keys (`v1_{PUBLIC_KEY}`)
- **Role-Based Subscribers**: Configurable accounts (Admin, Full Access, Limited, Peer) with timing-safe password verification and per-account concurrent connection limits
- **Multi-Peer Origin-Only Forwarding**: Connect brokers in multi-peer topologies (e.g., `Broker A -> B & C`, `Broker C -> B`) using Ed25519 JWTs (`AUTHORIZED_PEERS`) or Role 4 credentials; brokers forward **only** local observer data and never re-forward peer-received data, with cross-path packet deduplication
- **Remote Serial Access**: Bidirectional support for admin-issued `/serial/commands` and publisher-signed `/serial/responses`
- **Rich `$SYS/broker/#` Telemetry**: Retained JSON & scalar metrics updated every 10 seconds for Role 1 (`admin`) subscribers in **MQTT Explorer** (uptime, memory/CPU, connected publishers by IATA region, subscriber account usage, peer bridge status, rolling 1m/5m traffic rates, blocked IPs, and active violators in temporary mute timeout)
- **Abuse Detection & 4-Hour Temporary Mute Timeout**: $O(1)$ ring-buffer rate tracking, SHA-256 duplicate packet detection, raw LoRa packet size validation, 24h IATA region change limits, configurable temporary mute timeout (`ABUSE_MUTE_DURATION_MS`, default 4 hours), batched transactional SQLite persistence, and retained `/internal` admin telemetry
- **Connection Rate Limiting**: IP-based rate limiter (10 failed/unauthenticated attempts in 60s blocks IP for 5 minutes) across HTTP, WebSocket, and TCP listeners
- **Production-Ready Docker**: Pre-built multi-arch containers (`linux/amd64` and `linux/arm64`) on GHCR with automatic `PUID`/`PGID` privilege dropping and `/health` (`/healthz`) endpoints

---

## Supported Architectures

The automated GitHub Actions workflow publishes multi-architecture images to the GitHub Container Registry (`ghcr.io`):

| Architecture | Platform Tag | Target Environments & Devices |
| :--- | :--- | :--- |
| **x86_64 / AMD64** | `linux/amd64` | Standard Intel & AMD PC / Server hardware, unRAID, x86 VPS |
| **ARM64 / AArch64** | `linux/arm64` | Raspberry Pi 4 / 5 (64-bit OS), Apple Silicon, AWS Graviton, Oracle ARM |

---

## Docker Quick Start

### Option 1: Docker Compose (Recommended)

Run directly with `docker compose`:

```yaml
services:
  meshcore-broker:
    image: ghcr.io/dhovin/meshcore-mqtt-broker:latest
    container_name: meshcore-mqtt-broker
    restart: unless-stopped
    ports:
      - "8883:8883"
      # Plain TCP MQTT is unencrypted; bind to localhost or a private network if enabled:
      # - "127.0.0.1:1883:1883"
    environment:
      - PUID=1000
      - PGID=1000
      - MQTT_HOST=0.0.0.0
      - MQTT_WS_PORT=8883
      # Set your expected JWT audience, or leave empty to skip audience validation
      - AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com
      # Subscriber accounts format: username:password:role:maxConnections (1=Admin, 2=Full, 3=Limited)
      - SUBSCRIBER_MAX_CONNECTIONS_DEFAULT=2
      - SUBSCRIBER_1=admin:your-admin-password:1:10
      - SUBSCRIBER_2=viewer:your-viewer-password:2
      # Optional HTTP Browser Redirect URL for / (leave empty for built-in 200 OK status; /health and /healthz always return 200 OK)
      # - HTTP_REDIRECT_URL=https://your-custom-site-or-analyzer.com
      # Optional Standard TCP MQTT listener (for Mosquitto bridges)
      # - ENABLE_TCP_MQTT=true
      # - MQTT_TCP_PORT=1883
    volumes:
      - meshcore_data:/data

volumes:
  meshcore_data:
```

Start the service:

```bash
docker compose up -d
docker compose logs -f
```

### Option 2: Docker CLI (`docker run`)

```bash
docker run -d \
  --name meshcore-mqtt-broker \
  --restart unless-stopped \
  -p 8883:8883 \
  -e AUTH_EXPECTED_AUDIENCE="mqtt.yourdomain.com" \
  -e SUBSCRIBER_1="admin:your-admin-password:1:10" \
  -e SUBSCRIBER_2="viewer:your-viewer-password:2" \
  -v meshcore_data:/data \
  ghcr.io/dhovin/meshcore-mqtt-broker:latest
```

### Option 3: Building Locally from Source

```bash
# Build local Docker image
docker compose up -d --build

# Or build manually using Docker Buildx:
docker build -t meshcore-broker:latest .
```

---

## Deployment Guides

- [Cloudflare Tunnels Guide](docs/cloudflare-tunnels.md) *(Recommended for TLS and public WebSocket ingress)*
- [Portainer Deployment Guide](docs/portainer.md)
- [unRAID Deployment Guide](docs/unraid.md)
- [Security Audit & Hardening Documentation](docs/security-fixes.md)

---

## Authentication

### 1. Publisher Authentication (MeshCore Nodes / Ingestors)

#### Username Format
```
v1_{UPPERCASE_PUBLIC_KEY}
```
Where `{UPPERCASE_PUBLIC_KEY}` is the node's 64-character hexadecimal Ed25519 public key.

Example: `v1_7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400`

#### Password Format
The password is a JWT-style authentication token (`header.payload.signature`) signed with your MeshCore Ed25519 private key using `orlp/ed25519`, which is used in the MeshCore firmware and in the `@michaelhart/meshcore-decoder` library's `createAuthToken` function.

```javascript
import { createAuthToken } from '@michaelhart/meshcore-decoder';

const privateKey = 'YOUR_64_BYTE_PRIVATE_KEY_HEX'; // MeshCore format
const publicKey = 'YOUR_32_BYTE_PUBLIC_KEY_HEX';

const password = await createAuthToken(
  {
    publicKey: publicKey,
    aud: 'mqtt.yourdomain.com', // Must match AUTH_EXPECTED_AUDIENCE if set
    iat: Math.floor(Date.now() / 1000),
    // Optional: add expiration (automatically enforced by verifyAuthToken when present)
    // exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
  },
  privateKey,
  publicKey
);
```

### 2. Subscriber Authentication (Dashboards, Analyzers & Bridges)

Subscribers authenticate using configured username/password accounts (`SUBSCRIBER_1`, `SUBSCRIBER_2`, etc.) verified via constant-time (`crypto.timingSafeEqual`) comparison.

Format:
```
SUBSCRIBER_N=username:password:role:maxConnections
```
- **Sequential Numbering**: Accounts must be numbered sequentially starting at `SUBSCRIBER_1` without gaps (`SUBSCRIBER_1`, `SUBSCRIBER_2`, `SUBSCRIBER_3`, ...). The broker stops loading at the first missing index.
- **`role`**: `1` (Admin), `2` (Full Access), `3` (Limited), or `4` (Peer). Defaults to `3` (Limited) if omitted or invalid.
- **`maxConnections`**: Maximum concurrent connections allowed for this username. Specify a positive integer to override, or `D` / omit to use `SUBSCRIBER_MAX_CONNECTIONS_DEFAULT` (default: `2`).

#### Subscriber Roles & Permissions

| Role | Access Level | Topic Access | Publish Permissions | Payload Filtering |
| :--- | :--- | :--- | :--- | :--- |
| **Role 1 (`admin`)** | Admin | All topics including `meshcore/#`, `/internal` (PII & trust state), `/serial/*`, and `$SYS/#` | Can publish empty retained messages (`retain: true`, 0-byte payload) to delete retained messages, publish to `meshcore/{IATA}/{PUBLIC_KEY}/serial/commands`, and publish bridge connection state notifications to `$SYS/broker/connection/#` | None (unfiltered) |
| **Role 2 (`full_access`)** | Full Access | All public `meshcore/#` topics; blocked from `/internal`, `/serial/*`, and `$SYS/#` | Can publish bridge connection state notifications to `$SYS/broker/connection/#` (e.g., Mosquitto bridges); otherwise subscribe-only | None (unfiltered) |
| **Role 3 (`limited`)** | Limited *(Default)* | All public `meshcore/#` topics; blocked from `/internal`, `/serial/*`, and `$SYS/#` | None (subscribe-only) | Sensitive fields stripped: `SNR`, `RSSI`, `score` removed from `/packets`; `stats`, `model`, `firmware_version` removed from `/status` |
| **Role 4 (`peer`)** | Inbound Peer Broker | None (publish-only) | Can publish validated observer telemetry (`packets`, `status`, `neighbors`, `raw`) on `meshcore/{IATA}/{PUBLIC_KEY}/{subtopic}` | N/A |

### 3. Multi-Peer Origin-Only Forwarding (Broker-to-Broker Interconnect)

Brokers can push local observer telemetry (`packets`, `status`, `neighbors`, `raw`) to one or more peer brokers over outbound MQTT-over-WebSocket connections (`PEER_1`, `PEER_2`, ...):
- **Strict Origin-Only Forwarding**: A broker **only** forwards packets published directly by its own local observers (`ClientType.PUBLISHER`). Packets received from another peer broker (`ClientType.PEER`) are never re-forwarded, preventing loops or duplicate hops in multi-peer topologies (e.g., `Broker A -> B & C` and `Broker C -> B`).
- **Dual-Connected Observer Deduplication**: A SHA-256 cross-path deduplication cache (with TTL matched to `PEER_QUEUE_TTL_MS`, default 10 minutes) filters duplicate packets when an observer is simultaneously connected to multiple brokers, while preserving backup peer forwarding paths if a direct link is down.
- **Two Peer Authentication Modes**:
  1. **Ed25519 Public Key JWT (Recommended)**: Outbound broker signs a 24h JWT (auto-rotated every 12h) using `PEER_PRIVATE_KEY` (or a persistent Ed25519 identity auto-generated on startup in `/data/peer-identity.json`, whose 64-character hex public key is displayed in the startup banner and `$SYS/broker/public_key`). The receiving broker authorizes the peer by listing its 64-character hex public key in `AUTHORIZED_PEERS`.
     ```env
     # On Broker A (pushes to Broker B and Broker C):
     PEER_1=wss://broker-b.yourdomain.com|broker-b.yourdomain.com
     PEER_2=wss://broker-c.yourdomain.com|broker-c.yourdomain.com

     # On Broker C (accepts from Broker A, and pushes its own local observers to Broker B):
     AUTHORIZED_PEERS=PUBLIC_KEY_OF_BROKER_A
     PEER_1=wss://broker-b.yourdomain.com|broker-b.yourdomain.com

     # On Broker B (accepts from both Broker A and Broker C):
     AUTHORIZED_PEERS=PUBLIC_KEY_OF_BROKER_A,PUBLIC_KEY_OF_BROKER_C
     ```
  2. **Role 4 Username/Password**: Configure a `SUBSCRIBER_N=peer_user:peer_pass:4:2` account on the receiving broker and set `PEER_1=wss://broker-b.yourdomain.com|peer_user|peer_pass` on the sending broker.

---

## Topics & Message Validation

### Topic Format
Publishers can only publish to topics matching the 4-part prefix:

```
meshcore/{IATA_CODE}/{PUBLIC_KEY}/{subtopic}
```

Examples:
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/packets`
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/status`
- `meshcore/PDX/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/internal` *(Broker-published, Admin-only)*
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/serial/commands` *(Admin-published, Publisher-subscribed)*
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/serial/responses` *(Publisher-published JWT, Admin-subscribed)*

### Validation & Normalization Rules
1. **`{IATA_CODE}`**:
   - Must be a valid 3-letter uppercase IATA international airport code (validated via `airport-utils`, e.g., `SEA`, `PDX`, `BOS`) or `test` for testing.
   - The placeholder `XXX` or any invalid IATA code is rejected and **immediately disconnects the client**.
   - Normalized automatically to uppercase (e.g., `SEA`) or lowercase `test`.
2. **`{PUBLIC_KEY}`**:
   - Must be 64 hexadecimal characters matching the publisher's authenticated public key (normalized to uppercase).
   - Mismatched or malformed public keys in the topic are rejected and **immediately disconnect the client**.
3. **Allowed Publisher Subtopics & Payload Validation (`packets`, `status`, `neighbors`, `raw`, `serial/responses`)**:
   - Publishers are permitted to publish to subtopics in the allowlist: `packets`, `status`, `neighbors`, `raw`, and `serial/responses`.
   - Publishes to unrecognized subtopics or direct client publishes to `/internal` are **silently dropped** without disconnecting the observer socket (avoiding client reconnect storms).
   - Payloads must not exceed `MQTT_MAX_PACKET_BYTES` (default: `65536` bytes / 64 KB).
   - Standard subtopics (`packets`, `status`, `neighbors`, `raw`) must be valid UTF-8 JSON containing an `origin_id` field matching the authenticated `PUBLIC_KEY` (case-insensitive).
4. **Peer Broker Trust Model & Rate Limiting**:
   - Authorized peer brokers (`AUTHORIZED_PEERS` Ed25519 public keys or Role 4 `PEER` accounts) are **trusted broker-to-broker links** that forward validated observer telemetry (`packets`, `status`, `neighbors`, `raw`) on behalf of their local observers (`origin_id` must match the `{PUBLIC_KEY}` in the topic). Only peer keys and credentials under trusted administrative control should be added to `AUTHORIZED_PEERS` or Role 4 accounts.
   - Inbound peer traffic is rate-limited per peer identity via `PEER_RATE_LIMIT_PER_SEC` (default: `500` msg/s, with burst capacity set to `max(PEER_QUEUE_MAX_SIZE, 2 * PEER_RATE_LIMIT_PER_SEC)` so a full reconnect backlog drain is accepted without loss), while outbound queue draining is paced to `PEER_RATE_LIMIT_PER_SEC`. Keep `PEER_RATE_LIMIT_PER_SEC` and `PEER_QUEUE_MAX_SIZE` matched across peered brokers (or set the receiver's values at or above the sender's). Peer-forwarded traffic does not charge the individual observer's local rate-limit bucket or duplicate-flood mute counter (preventing reconnect queue drains from muting active observers).
5. **Special Subtopic Behaviors**:
   - **`/status` (`meshcore/{IATA}/{PUBLIC_KEY}/status`)**:
     - **Retain Flag Stripping**: Any `retain: true` flag on `/status` messages (including Last Will and Testament / LWT offline messages) is automatically stripped so stale status payloads are never retained.
     - **Stale Status / LWT Race Protection**: The broker tracks the latest `timestamp` per `origin_id` on `/status` messages and drops out-of-order status messages with an older timestamp than already seen.
     - **Role 3 Filtering**: `stats`, `model`, and `firmware_version` fields are stripped when forwarding to Role 3 (`limited`) subscribers.
   - **`/packets` (`meshcore/{IATA}/{PUBLIC_KEY}/packets`)**:
     - **Role 3 Filtering**: Radio metrics (`SNR`, `RSSI`, and `score`) are stripped when forwarding to Role 3 (`limited`) subscribers.
   - **`/internal` (`meshcore/{IATA}/{PUBLIC_KEY}/internal`)**:
     - **Broker-Generated Only**: Direct client publishes to `/internal` are denied.
     - Whenever a publisher publishes a valid JSON message, the broker automatically publishes a **retained** message to `meshcore/{IATA}/{PUBLIC_KEY}/internal` containing `origin_id`, `timestamp`, `jwt_payload` (decoded JWT claims / PII), and `trust_state` (abuse detector metrics).
     - Forwarded **only** to Role 1 (`admin`) subscribers.
   - **`/serial/commands` & `/serial/responses` (Remote Serial Access)**:
     - **Commands**: Only Role 1 (`admin`) subscribers may publish to `meshcore/{IATA}/{PUBLIC_KEY}/serial/commands`. Publishers are publish-only **except** they may subscribe to their own `meshcore/{IATA}/{PUBLIC_KEY}/serial/commands` topic (subscribing to any other topic disconnects the publisher).
     - **Responses**: Publishers may publish to `meshcore/{IATA}/{PUBLIC_KEY}/serial/responses`. Unlike standard JSON subtopics, the payload must be a valid 3-part base64url-encoded JWT (`header.payload.signature`).
     - Both `/serial/*` subtopics are blocked from forwarding to non-admin subscribers (Roles 2 and 3).

---

## `$SYS/broker/#` Telemetry (MQTT Explorer & Admin Monitoring)

For Role 1 (`admin`) subscribers, the broker publishes a rich hierarchy of **retained** operational metrics under `$SYS/broker/#` every `MQTT_SYS_INTERVAL_MS` (default: `10000` ms / 10 seconds), deduplicating unchanged scalar values to minimize network traffic.

This hybrid layout is optimized for **MQTT Explorer**:
- **JSON Summary Topics** display formatted, syntax-highlighted JSON with change-diffing in MQTT Explorer's value panel.
- **Scalar Subtopics** display values inline in the topic tree and can be clicked in MQTT Explorer to plot real-time line graphs.

| Topic | Type | Description |
| :--- | :---: | :--- |
| `$SYS/broker/summary` | JSON | All-in-one snapshot of broker health, public key, clients, active IATA regions, traffic rates, and security |
| `$SYS/broker/version` | String | Broker version, Aedes version, and Node.js runtime version |
| `$SYS/broker/public_key` | String | This broker instance's 64-character Ed25519 peer public key |
| `$SYS/broker/started_at` | String | ISO-8601 timestamp when the broker started |
| `$SYS/broker/uptime` | Number | Broker uptime in seconds |
| `$SYS/broker/uptime/formatted` | String | Human-readable uptime (`Xd Xh Xm Xs`) |
| `$SYS/broker/system` | JSON | Memory (`rssMb`, `heapUsedMb`, `heapTotalMb`, `externalMb`), CPU %, event loop lag, listeners, retained & subscription counts |
| `$SYS/broker/system/memory/rss_mb` | Number | Process Resident Set Size (MB) |
| `$SYS/broker/system/memory/heap_used_mb` | Number | V8 Heap Used (MB) |
| `$SYS/broker/system/memory/heap_total_mb` | Number | V8 Heap Total (MB) |
| `$SYS/broker/system/cpu_percent` | Number | Process CPU utilization (%) over the last interval |
| `$SYS/broker/system/event_loop_lag_ms` | Number | Event loop timer drift / lag (ms) |
| `$SYS/broker/system/retained_messages` | Number | Total active retained messages (excluding `$SYS/#`) |
| `$SYS/broker/system/subscriptions` | Number | Total active client topic subscriptions |
| `$SYS/broker/clients` | JSON | Full breakdown of connected clients, peak concurrent, publishers, subscribers by role & account, and WebSocket vs. TCP |
| `$SYS/broker/clients/connected` | Number | Currently connected clients |
| `$SYS/broker/clients/maximum` | Number | Peak concurrent connected clients since startup |
| `$SYS/broker/clients/publishers` | Number | Currently connected MeshCore publishers |
| `$SYS/broker/clients/peers` | Number | Currently connected inbound peer brokers |
| `$SYS/broker/clients/subscribers` | Number | Currently connected subscribers |
| `$SYS/broker/peers` | JSON | Full inbound & outbound peer snapshot (`publicKey`, `inbound`, `outboundTotals`, and per-peer details) |
| `$SYS/broker/peers/public_key` | String | This broker instance's 64-character Ed25519 peer public key |
| `$SYS/broker/peers/authorized_keys_count` | Number | Count of configured `AUTHORIZED_PEERS` public keys |
| `$SYS/broker/peers/inbound_connected` | Number | Currently connected inbound peer brokers |
| `$SYS/broker/peers/inbound/received_packets` | Number | Total valid packets received from inbound peers |
| `$SYS/broker/peers/inbound/received_bytes` | Number | Total payload bytes received from inbound peers |
| `$SYS/broker/peers/inbound/duplicates_filtered` | Number | Cross-path duplicates filtered from inbound peers |
| `$SYS/broker/peers/inbound/rate_limited` | Number | Inbound peer packets dropped by `PEER_RATE_LIMIT_PER_SEC` |
| `$SYS/broker/peers/inbound/invalid_dropped` | Number | Malformed or unauthorized packets dropped from inbound peers |
| `$SYS/broker/peers/inbound/{PEER_ID}` | JSON | Detailed stats for a specific inbound peer (`connected`, `clientIp`, `uptimeSeconds`, `packetsReceived`, `bytesReceived`, `bySubtopic`, `duplicatesFiltered`, `rateLimited`) + scalar subtopics |
| `$SYS/broker/peers/outbound_connected` | Number | Currently connected outbound peer bridges |
| `$SYS/broker/peers/outbound_count` | Number | Configured outbound peer bridges |
| `$SYS/broker/peers/outbound/forwarded_packets` | Number | Total packets forwarded across all outbound peers |
| `$SYS/broker/peers/outbound/forwarded_bytes` | Number | Total bytes forwarded across all outbound peers |
| `$SYS/broker/peers/outbound/queued_packets` | Number | Total packets currently queued across all outbound peers |
| `$SYS/broker/peers/outbound/queued_bytes` | Number | Total bytes currently queued across all outbound peers |
| `$SYS/broker/peers/outbound/dropped_packets` | Number | Total packets dropped across all outbound peer queues |
| `$SYS/broker/peers/outbound/{PEER_ID}` | JSON | Detailed stats for a specific outbound peer (`connected`, `draining`, `url`, `targetAudience`, `authMode`, `uptimeSeconds`, `lastError`, `forwarded`, `forwardedBytes`, `forwardedBySubtopic`, `queued`, `dropped`, `coalescedStatus`) + scalar subtopics |
| `$SYS/broker/clients/websocket` | Number | Active WebSocket connections |
| `$SYS/broker/clients/tcp` | Number | Active plain TCP connections |
| `$SYS/broker/clients/total_connections` | Number | Lifetime connections since startup |
| `$SYS/broker/clients/total_disconnects` | Number | Lifetime disconnections since startup |
| `$SYS/broker/clients/subscribers_by_account` | JSON | Per-account `{ role, active, max }` connection usage |
| `$SYS/broker/regions` | JSON | Summary of all IATA regions (`connectedPublishers`, `activePublishers1h`, `trackedPublishers`, `totalPacketsReceived`, `connectedPublisherPrefixes`) |
| `$SYS/broker/regions/active_count` | Number | Count of IATA regions with currently connected or 1h-active publishers |
| `$SYS/broker/regions/{IATA}` | JSON | Detailed stats for a specific IATA region (e.g., `SEA`, `PDX`, `BOS`, `test`) |
| `$SYS/broker/regions/{IATA}/publishers` | Number | Currently connected publishers in `{IATA}` |
| `$SYS/broker/regions/{IATA}/packets` | Number | Total packets received from publishers in `{IATA}` |
| `$SYS/broker/traffic` | JSON | Total messages & bytes received, 1m/5m rolling rates, subtopic breakdown, and stale status filter counts |
| `$SYS/broker/traffic/messages/received` | Number | Total client messages published |
| `$SYS/broker/traffic/messages/bytes_received` | Number | Total client payload bytes received |
| `$SYS/broker/traffic/rate/messages_per_sec_1m` | Number | Rolling 1-minute message rate (`msg/s`) |
| `$SYS/broker/traffic/rate/messages_per_sec_5m` | Number | Rolling 5-minute message rate (`msg/s`) |
| `$SYS/broker/traffic/rate/bytes_per_sec_1m` | Number | Rolling 1-minute throughput (`bytes/s`) |
| `$SYS/broker/traffic/rate/bytes_per_sec_5m` | Number | Rolling 5-minute throughput (`bytes/s`) |
| `$SYS/broker/traffic/by_subtopic/*` | Number | Individual counters for `packets`, `status`, `serial_commands`, `serial_responses`, and `internal` |
| `$SYS/broker/traffic/stale_status_filtered` | Number | Out-of-order `/status` (LWT race) messages blocked |
| `$SYS/broker/traffic/duplicates_filtered` | Number | Cross-path duplicate packets filtered across peer/dual-connected paths |
| `$SYS/broker/traffic/peer_rate_limited` | Number | Inbound peer packets dropped due to exceeding `PEER_RATE_LIMIT_PER_SEC` |
| `$SYS/broker/security` | JSON | Combined security telemetry: auth failures, unauthorized publishes, IP rate limiter, and abuse detector summary |
| `$SYS/broker/security/auth_failures` | Number | Total failed authentication attempts |
| `$SYS/broker/security/unauthorized_publishes` | Number | Total denied publish attempts |
| `$SYS/broker/security/rate_limiter` | JSON | Rate limiter state including list of currently blocked IPs and remaining block durations |
| `$SYS/broker/security/rate_limiter/blocked_ips_count` | Number | Currently blocked IP count |
| `$SYS/broker/security/rate_limiter/tracked_ips_count` | Number | Currently tracked failing IP count |
| `$SYS/broker/security/rate_limiter/total_blocked_attempts` | Number | Total connection/HTTP attempts rejected due to IP blocks |
| `$SYS/broker/security/abuse_detector` | JSON | Abuse detector summary including `muteDurationSeconds`, `violators`, and top flagged publishers |
| `$SYS/broker/security/abuse_detector/violators` | JSON | Active violators currently in temporary timeout (`muted` or `would_mute`) with `mutedUntil` and `remainingMuteSeconds` |
| `$SYS/broker/security/abuse_detector/muted_count` | Number | Publishers currently in `'muted'` status (`ABUSE_ENFORCEMENT_ENABLED=true`) |
| `$SYS/broker/security/abuse_detector/would_mute_count` | Number | Publishers in `'would_mute'` status (`ABUSE_ENFORCEMENT_ENABLED=false`) |
| `$SYS/broker/security/abuse_detector/anomalies_total` | Number | Total anomalies across tracked publishers |
| `$SYS/broker/security/abuse_detector/duplicates_total` | Number | Total duplicate packets detected across tracked publishers |
| `$SYS/broker/security/abuse_detector/silenced_total` | Number | Total packets silenced from muted publishers |

---

## Abuse Detection, Rate Limiting & Security

### 1. IP Connection Rate Limiter (`RateLimiter`)
- Tracks failed or unauthenticated connection attempts by client IP across the **HTTP**, **WebSocket**, and **TCP MQTT** servers.
- **Threshold**: `10` failed/unauthenticated connections within a `60`-second window blocks the IP for `300` seconds (5 minutes).
- **Memory Bounds**: Capped at `10,000` IP records with a 5-minute background cleanup timer and prioritized eviction (expired records first, then oldest unblocked records; active blocks are never evicted).
- **Proxy Header Support**: On HTTP/WebSocket connections, `getClientIP` inspects `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` before falling back to socket remote address (ideal behind Cloudflare Tunnels or reverse proxies).

### 2. Publisher Abuse Detector (`AbuseDetector`)
Tracks per-publisher behavioral metrics in memory and persists state to a SQLite database (`ABUSE_PERSISTENCE_PATH`):
- **Token-Bucket Rate Limiting**: Initialized with `ABUSE_BUCKET_CAPACITY` tokens and refilled at `ABUSE_BUCKET_REFILL_RATE` tokens/second.
- **Duplicate Packet Detection**: Computes SHA-256 hashes of payloads within a sliding window (`ABUSE_DUPLICATE_WINDOW_SIZE` / `ABUSE_DUPLICATE_WINDOW_MS`). Records anomalies if a single packet is seen more than `ABUSE_MAX_DUPLICATES_PER_PACKET` times or if the duplicate ratio exceeds `ABUSE_DUPLICATE_RATE_THRESHOLD` over `ABUSE_DUPLICATE_RATE_WINDOW_MS` (evaluated after at least 20 packets).
- **Raw LoRa Packet Size Check**: If a published JSON message includes a hex-encoded `raw` field whose byte length (`raw.length / 2`) exceeds `ABUSE_MAX_PACKET_SIZE` (default `255` bytes), a `packet_size` anomaly is recorded.
- **IATA Change Tracking**: Monitors how many times a publisher changes its `{IATA_CODE}` region within a rolling 24-hour window (`ABUSE_MAX_IATA_CHANGES_24H`).
- **Telemetry, 4-Hour Temporary Mute Timeout & Enforcement (`ABUSE_ENFORCEMENT_ENABLED`, `ABUSE_MUTE_DURATION_MS`)**:
  - When `ABUSE_ENFORCEMENT_ENABLED=true`, exceeding rate limits, IATA change limits, or `ABUSE_ANOMALY_THRESHOLD` places the publisher in a temporary `'muted'` timeout for `ABUSE_MUTE_DURATION_MS` (default `14400000` ms / 4 hours, recording `mutedAt`, `mutedUntil`, and `muteReason`). While muted, packets from that publisher are **silently dropped** without disconnecting its WebSocket connection (preventing client reconnect storms). When `ABUSE_ENFORCEMENT_ENABLED=false`, the broker logs `WOULD MUTE` and transitions `status` to `'would_mute'` for the same timeout window.
  - Once `mutedUntil` expires, the publisher is **automatically restored** to `'allowed'` with a refreshed token bucket and reset short-term anomaly/duplicate counters.
  - Trust metrics are published to `meshcore/{IATA}/{PUBLIC_KEY}/internal` (throttled to once every 30s per observer or immediately on status change) under `trust_state`, and active violators are listed in `$SYS/broker/security/abuse_detector/violators` and `$SYS/broker/security/abuse_detector`.
- **Bounded Persistence**: State is saved to SQLite every `ABUSE_PERSISTENCE_INTERVAL_MS` (default 5 minutes) and on `SIGINT`/`SIGTERM` shutdown. Clients with no packet activity for longer than `ABUSE_STATE_RETENTION_MS` (default 7 days) are automatically evicted from memory and disk.

### 3. HTTP Health Check & Browser Redirect
- `GET /health` and `GET /healthz` always return `HTTP 200 OK` with `{"status":"ok","service":"MeshCore MQTT Broker"}` (used by Docker healthchecks and uptime monitors).
- Other non-WebSocket HTTP requests return an `HTTP 302` redirect to `HTTP_REDIRECT_URL` when configured, or fall back to the `HTTP 200 OK` JSON status response if `HTTP_REDIRECT_URL` is empty.

---

## Configuration Reference

All configuration is managed via environment variables in `.env` or container environment variables.

> **Important Note for Non-Docker Deployments**: The `Dockerfile` pre-populates default values for all environment variables. When running directly on a host (`npm start` / `npm run dev`) or via Nixpacks without Docker `ENV` defaults, copy `.env.example` to `.env` so all required variables are defined (`src/config.ts` validates required variables at startup and exits if any are undefined).

```bash
cp .env.example .env
```

### Server, Network & Auth Variables

| Variable | Required in `.env` | Default | Description |
| :--- | :---: | :--- | :--- |
| `MQTT_WS_PORT` | **Yes** | `8883` | Port for the HTTP / WebSocket MQTT listener |
| `MQTT_HOST` | **Yes** | `0.0.0.0` | Host interface to bind listeners |
| `AUTH_EXPECTED_AUDIENCE` | **Yes** *(can be empty)* | `""` | Expected `aud` claim in publisher JWT tokens (leave empty to skip audience check) |
| `ENABLE_TCP_MQTT` | No | `false` | Set to `true` to enable the plain TCP MQTT listener |
| `MQTT_TCP_PORT` | No | `1883` | Port for the optional plain TCP MQTT listener |
| `HTTP_REDIRECT_URL` | No | `""` | Optional URL to redirect (`302`) non-WebSocket HTTP requests (except `/health` & `/healthz`) |
| `MQTT_MAX_PACKET_BYTES` | No | `65536` | Maximum allowed MQTT publish payload size in bytes (`MqttStreamValidator` allows `+4096` bytes headroom for headers/topic) |
| `MQTT_SYS_INTERVAL_MS` | No | `10000` | Interval (`ms`) between retained `$SYS/broker/#` telemetry updates (default: 10 seconds) |
| `LOG_LEVEL` | No | `info` | Logging verbosity (`info` or `debug`) |
| `PUID` | No *(Docker only)* | `1000` | UID used by `docker-entrypoint.sh` for `/data` ownership and privilege drop |
| `PGID` | No *(Docker only)* | `1000` | GID used by `docker-entrypoint.sh` for `/data` ownership and privilege drop |

### Subscriber & Peer Variables

| Variable | Required in `.env` | Default | Description |
| :--- | :---: | :--- | :--- |
| `SUBSCRIBER_MAX_CONNECTIONS_DEFAULT` | **Yes** | `2` | Default max concurrent connections per subscriber username |
| `SUBSCRIBER_1`, `SUBSCRIBER_2`, ... | No | — | Sequential accounts in format `username:password:role:maxConnections` (`role`: `1`=Admin, `2`=Full, `3`=Limited, `4`=Peer) |
| `PEER_PRIVATE_KEY` | No | `""` | Optional 64-char or 128-char hex Ed25519 private key for outbound peer JWT signing (auto-generated on startup in `/data/peer-identity.json` and exposed in the startup banner + `$SYS/broker/public_key` if omitted) |
| `AUTHORIZED_PEERS` | No | `""` | Comma-separated 64-char hex Ed25519 public keys of inbound peer brokers authorized to publish |
| `PEER_1`, `PEER_2`, ... | No | — | Outbound peer targets (with or without explicit port; supports `\|` or `:` delimiters): `ws(s)://host[:port]\|targetAudience` (Ed25519 JWT) or `ws(s)://host[:port]\|username\|password` (Role 4) |
| `PEER_QUEUE_MAX_SIZE` | No | `5000` | Maximum queued packets per outbound peer during disconnects |
| `PEER_QUEUE_MAX_BYTES` | No | `8388608` | Maximum queued bytes per outbound peer (`8 MiB`) |
| `PEER_QUEUE_TTL_MS` | No | `600000` | Maximum packet age in outbound peer queue (`10 min`) |
| `PEER_RATE_LIMIT_PER_SEC` | No | `500` | Outbound drain rate & inbound sustained msg/s limit per peer (burst `max(PEER_QUEUE_MAX_SIZE, 2x)`) |

### Abuse Detection & Persistence Variables

| Variable | Required in `.env` | Default | Description |
| :--- | :---: | :--- | :--- |
| `ABUSE_ENFORCEMENT_ENABLED` | **Yes** | `false` | Silently drop packets from muted violators during their timeout when `true` |
| `ABUSE_MUTE_DURATION_MS` | No | `14400000` | Temporary mute timeout duration (`ms`, default 4 hours) before automatic unmute |
| `ABUSE_DUPLICATE_WINDOW_SIZE` | **Yes** | `100` | Max number of recent unique packet SHA-256 hashes retained per client |
| `ABUSE_DUPLICATE_WINDOW_MS` | **Yes** | `300000` | Sliding window (`ms`) to retain packet hashes for duplicate checks (5 min) |
| `ABUSE_DUPLICATE_THRESHOLD` | **Yes** | `10` | Base duplicate threshold configuration parameter |
| `ABUSE_MAX_DUPLICATES_PER_PACKET` | No | `5` | Max allowed copies of a single packet hash within the duplicate window |
| `ABUSE_DUPLICATE_RATE_THRESHOLD` | No | `0.3` | Max ratio (`0`–`1`) of duplicate packets allowed in the duplicate rate window (`30%`) |
| `ABUSE_DUPLICATE_RATE_WINDOW_MS` | No | `300000` | Window (`ms`) for measuring overall duplicate packet rate (5 min) |
| `ABUSE_BUCKET_CAPACITY` | **Yes** | `20` | Token bucket burst capacity per publisher |
| `ABUSE_BUCKET_REFILL_RATE` | **Yes** | `3` | Token bucket refill rate (tokens per second) |
| `ABUSE_MAX_PACKET_SIZE` | **Yes** | `255` | Max raw LoRa packet size in bytes (`message.raw.length / 2`) before logging an anomaly |
| `ABUSE_MAX_TOPICS_PER_DAY` | **Yes** | `3` | Max unique topics per day threshold parameter |
| `ABUSE_ANOMALY_THRESHOLD` | **Yes** | `10` | Total anomaly count that triggers client muting |
| `ABUSE_MAX_IATA_CHANGES_24H` | **Yes** | `3` | Max allowed IATA location code changes within a rolling 24-hour window |
| `ABUSE_TOPIC_HISTORY_SIZE` | **Yes** | `50` | Max topic history entries retained per client |
| `ABUSE_TOPIC_HISTORY_WINDOW_MS` | **Yes** | `86400000` | Topic history retention window (`ms`, 24 hours) |
| `ABUSE_PERSISTENCE_PATH` | **Yes** | `/data/abuse-detection.db` | File path for the SQLite trust state database |
| `ABUSE_PERSISTENCE_INTERVAL_MS` | **Yes** | `300000` | Interval (`ms`) between automatic SQLite database saves (5 min) |
| `ABUSE_STATE_RETENTION_MS` | No | `604800000` | Idle cutoff (`ms`, default 7 days) after which inactive client trust states are evicted |

---

## Mosquitto Bridge & Standard TCP MQTT Support

To allow an external Mosquitto server to pull topics from this broker natively over standard TCP MQTT (port 1883), enable the optional TCP listener:

> **Security Warning**: Port `1883` is plain, unencrypted MQTT (no TLS). Subscriber usernames and passwords travel in cleartext over this port. Only expose port `1883` on `localhost` (`127.0.0.1`), an internal Docker network, a private LAN/VPN (e.g., Tailscale/WireGuard), or behind a TLS-terminating proxy. Do not expose raw port `1883` directly to the public internet.

Set environment variables in your `.env` or `docker-compose.yml`:
```bash
ENABLE_TCP_MQTT=true
MQTT_TCP_PORT=1883
```

Then configure your external `mosquitto.conf`:
```ini
connection meshcore-pull-bridge
address your-meshcore-broker-host:1883
topic meshcore/# in 0
remote_username viewer
remote_password your-subscriber-password
```

---

## Local Development & Testing (Without Docker)

Requires **Node.js 24.22.1+**.

```bash
# 1. Install dependencies
npm install

# 2. Create local .env from template (and ensure ABUSE_PERSISTENCE_PATH points to a writable local path)
cp .env.example .env

# 3. Run unit & security tests
npm test

# 4. Compile TypeScript (outputs to dist/)
npm run build

# 5. Start the server (via tsx)
npm start

# Or run in development watch mode (via tsx watch):
npm run dev
```

---

## License

MIT License

Copyright (c) 2025 Michael Hart michaelhart@michaelhart.me (https://github.com/michaelhart)
