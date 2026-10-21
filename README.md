# meshcore-mqtt-broker

A WebSocket-based MQTT broker with MeshCore public key authentication, role-based subscribers, abuse detection, and optional standard TCP MQTT support.

[![Build and Push Docker Image](https://github.com/Dhovin/meshcore-mqtt-broker/actions/workflows/docker-build.yml/badge.svg)](https://github.com/Dhovin/meshcore-mqtt-broker/actions/workflows/docker-build.yml)

## Features

- **WebSocket MQTT**: Fast, reliable MQTT over WebSockets on port `8883`
- **Optional TCP MQTT**: Standard MQTT on port `1883` for Mosquitto bridges or internal forwarders
- **Public Key Authentication**: Ed25519 authentication for publishers using MeshCore public keys
- **Role-Based Subscribers**: Configurable accounts (Admin, Full Access, Limited) for dashboards & analyzers
- **Abuse Detection & Rate Limiting**: Token-bucket rate limiting, duplicate detection, and persistent SQLite tracking
- **Production-Ready Docker**: Pre-built multi-arch containers for AMD64 and ARM64 on GHCR

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
      # - "1883:1883" # Uncomment if TCP MQTT is enabled
    environment:
      - MQTT_HOST=0.0.0.0
      - MQTT_WS_PORT=8883
      - AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com
      # Subscriber accounts format: username:password:role (1=Admin, 2=Full, 3=Limited)
      - SUBSCRIBER_1=admin:your-admin-password:1
      - SUBSCRIBER_2=viewer:your-viewer-password:2
      # Optional HTTP Browser Redirect URL (leave empty for built-in 200 OK health status)
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
  -e SUBSCRIBER_1="admin:your-admin-password:1" \
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

---

## Authentication

### Username Format
```
v1_{UPPERCASE_PUBLIC_KEY}
```

Example: `v1_7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400`

### Password Format
The password is a JWT-style authentication token signed with your MeshCore Ed25519 private key using orlp/ed25519, which is used in the MeshCore firmware and in the `@michaelhart/meshcore-decoder` library's `createAuthToken` function.

```javascript
import { createAuthToken } from '@michaelhart/meshcore-decoder';

const privateKey = 'YOUR_64_BYTE_PRIVATE_KEY_HEX'; // MeshCore format
const publicKey = 'YOUR_32_BYTE_PUBLIC_KEY_HEX';

const password = await createAuthToken(
  {
    publicKey: publicKey,
    aud: 'mqtt.yourdomain.com', // Must match AUTH_EXPECTED_AUDIENCE in .env
    iat: Math.floor(Date.now() / 1000),
    // Optional: add expiration
    // exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
  },
  privateKey,
  publicKey
);
```

The token format is: `header.payload.signature` where the signature is verified using Ed25519.

---

## Configuration

All configuration is done via environment variables in a `.env` file or container environment.

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# MQTT Server Settings
MQTT_WS_PORT=8883
MQTT_HOST=0.0.0.0

# Optional Standard TCP MQTT listener (for Mosquitto bridges)
ENABLE_TCP_MQTT=false
MQTT_TCP_PORT=1883

# Authentication Settings
# Expected audience claim in JWT tokens (leave empty to skip validation)
AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com

# HTTP Web Browser Redirect (Optional - leave blank for 200 OK status fallback)
HTTP_REDIRECT_URL=

# Subscribe-Only Users (read-only monitoring accounts)
# Format: SUBSCRIBER_N=username:password:role:maxConnections
SUBSCRIBER_1=admin:your-secure-password-here:1:10
SUBSCRIBER_2=viewer:another-secure-password:2
SUBSCRIBER_3=monitor:yet-another-password:3:D
```

**Subscribe-only users** can read messages but cannot publish. They're useful for monitoring, debugging, and administrative dashboards.

**Subscriber Roles**:
- **Role 1 (Admin)**: Full access including `/internal` topics (contains PII), `$SYS/*` system topics, and ability to delete retained messages
- **Role 2 (Full Access)**: Access to all public topics with no data filtering, cannot access `/internal` or `$SYS/*`
- **Role 3 (Limited)**: Access to public topics only with sensitive data filtered (SNR, RSSI, score, stats, model, firmware_version removed from messages)

---

## Mosquitto Bridge & Standard TCP MQTT Support

To allow an external Mosquitto server to pull topics from this broker natively over standard TCP MQTT (port 1883), enable the optional TCP listener:

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

## Local Development (Without Docker)

```bash
npm install
npm run build
npm start
```

---

## Topics

Publishers can only publish to topics with the following format:

- `meshcore/{IATA_CODE}/{PUBLIC_KEY}/{subtopic}`

Examples:
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/packets`
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/status`
- `meshcore/PDX/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/internal` (ADMIN-only - contains PII)

Where:
- `{IATA_CODE}` must be a valid 3-letter IATA airport code (e.g., SEA, PDX, BOS) or `test` for testing
- `{PUBLIC_KEY}` must be the full 64-character hex public key (matching your authenticated public key)
- `{subtopic}` can be any subtopic name (e.g., `packets`, `status`, `internal`)

**Important**: The `/internal` subtopic is ADMIN-only and contains PII (Personally Identifiable Information) from JWT payloads. Only subscribers with role 1 (admin) can access these topics.

Subscribers (read-only users) can subscribe to any topic including wildcards like `meshcore/#`.

---

## License

MIT License

Copyright (c) 2025 Michael Hart michaelhart@michaelhart.me (https://github.com/michaelhart)
