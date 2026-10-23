# meshcore-mqtt-broker

A WebSocket-based MQTT broker with MeshCore Ed25519 public key authentication, role-based subscribers, remote serial command routing, abuse detection & trust telemetry, connection rate limiting, and optional standard TCP MQTT support.

[![Build and Push Docker Image](https://github.com/Dhovin/meshcore-mqtt-broker/actions/workflows/docker-build.yml/badge.svg)](https://github.com/Dhovin/meshcore-mqtt-broker/actions/workflows/docker-build.yml)

## Features

- **WebSocket MQTT**: Fast, reliable MQTT over WebSockets on port `8883` (with 1 MB frame limit, streaming MQTT packet size validation, and bidirectional duplex backpressure)
- **Optional TCP MQTT**: Standard raw MQTT on port `1883` for Mosquitto bridges or internal forwarders
- **Public Key Authentication**: Ed25519 JWT authentication for publishers using MeshCore public keys (`v1_{PUBLIC_KEY}`)
- **Role-Based Subscribers**: Configurable accounts (Admin, Full Access, Limited) with timing-safe password verification and per-account concurrent connection limits
- **Remote Serial Access**: Bidirectional support for admin-issued `/serial/commands` and publisher-signed `/serial/responses`
- **Abuse Detection & Trust Telemetry**: Token-bucket rate tracking, SHA-256 duplicate packet detection, raw LoRa packet size validation, 24h IATA region change limits, SQLite state persistence with 7-day retention pruning, and retained `/internal` admin telemetry
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
- **`role`**: `1` (Admin), `2` (Full Access), or `3` (Limited). Defaults to `3` (Limited) if omitted or invalid.
- **`maxConnections`**: Maximum concurrent connections allowed for this username. Specify a positive integer to override, or `D` / omit to use `SUBSCRIBER_MAX_CONNECTIONS_DEFAULT` (default: `2`).

#### Subscriber Roles & Permissions

| Role | Access Level | Topic Access | Publish Permissions | Payload Filtering |
| :--- | :--- | :--- | :--- | :--- |
| **Role 1 (`admin`)** | Admin | All topics including `meshcore/#`, `/internal` (PII & trust state), `/serial/*`, and `$SYS/#` | Can publish empty retained messages (`retain: true`, 0-byte payload) to delete retained messages, and can publish to `meshcore/{IATA}/{PUBLIC_KEY}/serial/commands` | None (unfiltered) |
| **Role 2 (`full_access`)** | Full Access | All public `meshcore/#` topics; blocked from `/internal`, `/serial/*`, and `$SYS/#` | None (subscribe-only) | None (unfiltered) |
| **Role 3 (`limited`)** | Limited *(Default)* | All public `meshcore/#` topics; blocked from `/internal`, `/serial/*`, and `$SYS/#` | None (subscribe-only) | Sensitive fields stripped: `SNR`, `RSSI`, `score` removed from `/packets`; `stats`, `model`, `firmware_version` removed from `/status` |

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
3. **Standard Subtopic Payloads (`packets`, `status`, etc.)**:
   - Payloads must not exceed `MQTT_MAX_PACKET_BYTES` (default: `65536` bytes / 64 KB).
   - Must be valid UTF-8 JSON containing an `origin_id` field matching the authenticated `PUBLIC_KEY` (case-insensitive).
4. **Special Subtopic Behaviors**:
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
- **Telemetry & Enforcement (`ABUSE_ENFORCEMENT_ENABLED`)**:
  - When `ABUSE_ENFORCEMENT_ENABLED=true`, exceeding rate limits, IATA change limits, or `ABUSE_ANOMALY_THRESHOLD` transitions the publisher's trust state `status` to `'muted'` (recording `mutedAt` and `muteReason`). When `false`, the broker logs `WOULD MUTE` and keeps `status` as `'allowed'`.
  - Trust metrics are published in real time to `meshcore/{IATA}/{PUBLIC_KEY}/internal` under `trust_state` for administrative monitoring and downstream filtering.
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
| `PUID` | No *(Docker only)* | `1000` | UID used by `docker-entrypoint.sh` for `/data` ownership and privilege drop |
| `PGID` | No *(Docker only)* | `1000` | GID used by `docker-entrypoint.sh` for `/data` ownership and privilege drop |

### Subscriber Variables

| Variable | Required in `.env` | Default | Description |
| :--- | :---: | :--- | :--- |
| `SUBSCRIBER_MAX_CONNECTIONS_DEFAULT` | **Yes** | `2` | Default max concurrent connections per subscriber username |
| `SUBSCRIBER_1`, `SUBSCRIBER_2`, ... | No | — | Sequential subscriber accounts in format `username:password:role:maxConnections` |

### Abuse Detection & Persistence Variables

| Variable | Required in `.env` | Default | Description |
| :--- | :---: | :--- | :--- |
| `ABUSE_ENFORCEMENT_ENABLED` | **Yes** | `false` | Mark offending clients as `'muted'` in trust state when thresholds are exceeded |
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

Requires **Node.js 22+**.

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

# Or run in development mode (via ts-node/esm):
npm run dev
```

---

## License

MIT License

Copyright (c) 2025 Michael Hart michaelhart@michaelhart.me (https://github.com/michaelhart)
