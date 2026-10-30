# Deploying MeshCore MQTT Broker with Portainer

This guide details how to deploy and manage the **MeshCore MQTT Broker** using [Portainer](https://www.portainer.io/), an intuitive Web UI for Docker container management.

---

## Prerequisites

- An active Portainer instance (Portainer CE or BE).
- A supported host architecture: **x86_64 (`amd64`)** or **ARM64 (`arm64`)** (e.g., Raspberry Pi 4/5 64-bit, Apple Silicon, ARM/x86 VPS).
- Access to Portainer's Web UI with rights to create containers or stacks.
- Network access to port `8883` (WebSocket) and optionally `1883` (TCP, recommended only on a private network/localhost or behind TLS).

---

## Method 1: Deploying via Portainer Stacks (Recommended)

Portainer Stacks allows you to deploy applications using Docker Compose definitions directly from the Portainer interface or directly from a Git repository.

### Step 1: Navigate to Stacks

1. Log in to your Portainer dashboard.
2. Select your Environment (e.g., **local** or **primary**).
3. Click on **Stacks** in the left navigation sidebar.
4. Click **+ Add stack**.

### Step 2: Configure the Stack

1. **Name**: Enter `meshcore-mqtt-broker`.
2. **Build method**: Choose **Web editor** (or **Repository** if linking directly to your fork/repository).
3. **Web editor**: Paste the following Docker Compose configuration:

```yaml
services:
  meshcore-broker:
    image: ghcr.io/dhovin/meshcore-mqtt-broker:latest
    container_name: meshcore-mqtt-broker
    restart: unless-stopped
    ports:
      - "${MQTT_WS_PORT:-8883}:${MQTT_WS_PORT:-8883}"
      # Plain TCP MQTT (unencrypted): bind to localhost or a private network only if enabled
      # - "127.0.0.1:${MQTT_TCP_PORT:-1883}:${MQTT_TCP_PORT:-1883}"
    environment:
      - PUID=${PUID:-1000}
      - PGID=${PGID:-1000}
      - MQTT_WS_PORT=${MQTT_WS_PORT:-8883}
      - ENABLE_TCP_MQTT=${ENABLE_TCP_MQTT:-false}
      - MQTT_TCP_PORT=${MQTT_TCP_PORT:-1883}
      - MQTT_HOST=0.0.0.0
      - AUTH_EXPECTED_AUDIENCE=${AUTH_EXPECTED_AUDIENCE-}
      - HTTP_REDIRECT_URL=${HTTP_REDIRECT_URL:-}
      - MQTT_MAX_PACKET_BYTES=${MQTT_MAX_PACKET_BYTES:-65536}
      - MQTT_SYS_INTERVAL_MS=${MQTT_SYS_INTERVAL_MS:-10000}
      - SUBSCRIBER_MAX_CONNECTIONS_DEFAULT=${SUBSCRIBER_MAX_CONNECTIONS_DEFAULT:-2}
      - SUBSCRIBER_1=${SUBSCRIBER_1:-viewer1:your-secure-password-here:2}
      - SUBSCRIBER_2=${SUBSCRIBER_2:-admin:admin-password-here:1:10}
      - LOG_LEVEL=${LOG_LEVEL:-info}
      - AUTHORIZED_PEERS=${AUTHORIZED_PEERS:-}
      - PEER_1=${PEER_1:-}
      - ABUSE_ENFORCEMENT_ENABLED=${ABUSE_ENFORCEMENT_ENABLED:-false}
      - ABUSE_MUTE_DURATION_MS=${ABUSE_MUTE_DURATION_MS:-14400000}
      - ABUSE_PERSISTENCE_PATH=/data/abuse-detection.db
      - ABUSE_STATE_RETENTION_MS=${ABUSE_STATE_RETENTION_MS:-604800000}
    volumes:
      - meshcore_data:/data
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --max-redirect=0 --spider http://127.0.0.1:$${MQTT_WS_PORT:-8883}/health || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  meshcore_data:
    driver: local
```

### Step 3: Environment Variables

Scroll down to the **Environment variables** section in Portainer and click **+ Add environment variable** for each parameter you want to customize:

| Name | Example Value | Description |
| :--- | :--- | :--- |
| `PUID` / `PGID` | `1000` / `1000` | UID / GID for `/data` ownership and non-root execution |
| `MQTT_WS_PORT` | `8883` | Host and container port for WebSockets |
| `AUTH_EXPECTED_AUDIENCE` | `mqtt.yourdomain.com` | Expected JWT audience claim (leave empty to skip audience validation) |
| `SUBSCRIBER_MAX_CONNECTIONS_DEFAULT` | `2` | Default max concurrent connections per subscriber account |
| `SUBSCRIBER_1` | `viewer1:yourpassword:2` | Subscriber user (`user:pass:role:maxConns`, sequential from `SUBSCRIBER_1`) |
| `SUBSCRIBER_2` | `admin:adminpassword:1:10` | Admin subscriber user (`1`=Admin, `2`=Full, `3`=Limited) |
| `HTTP_REDIRECT_URL` | `https://yourdomain.com` | *(Optional)* Browser redirect URL for `/` (`/health` and `/healthz` always return 200 OK) |
| `ENABLE_TCP_MQTT` | `false` | Enable/disable standard TCP MQTT on `MQTT_TCP_PORT` (default `1883`, unencrypted — use on private networks/localhost only) |
| `MQTT_TCP_PORT` | `1883` | Port for optional standard TCP MQTT listener |
| `MQTT_MAX_PACKET_BYTES` | `65536` | Max allowed MQTT publish payload size in bytes (64 KB default) |
| `MQTT_SYS_INTERVAL_MS` | `10000` | Interval in ms between retained `$SYS/broker/#` telemetry updates for Admin subscribers (default 10s) |
| `ABUSE_ENFORCEMENT_ENABLED` | `false` | When `true`, offending publishers are marked `'muted'` in `/internal` trust state |
| `ABUSE_STATE_RETENTION_MS` | `604800000` | Idle retention cutoff in ms (default 7 days) before inactive client trust states are evicted |

### Step 4: Deploy the Stack

1. Scroll to the bottom and click **Deploy the stack**.
2. Portainer will pull `ghcr.io/dhovin/meshcore-mqtt-broker:latest`, create the volume `meshcore_data`, and start the container.

---

## Method 2: Deploying as a Standalone Container

If you prefer not to use Stacks, you can create the container directly in Portainer's Container menu.

### Step 1: Navigate to Containers

1. Go to **Containers** in the left navigation menu.
2. Click **+ Add container**.

### Step 2: Basic Configuration

- **Name**: `meshcore-mqtt-broker`
- **Image**: `ghcr.io/dhovin/meshcore-mqtt-broker:latest` *(multi-arch: `amd64` / `arm64`)*
- **Network ports configuration**:
  - Click **+ publish a new network port**
  - **host**: `8883` | **container**: `8883` (TCP)

### Step 3: Volumes

1. Under **Advanced container settings**, click the **Volumes** tab.
2. Click **+ map additional volume**.
3. **container**: `/data`
4. Choose **Volume** and select/create `meshcore_data` (or choose **Bind** and specify a host path like `/var/lib/meshcore/data` — the container entrypoint automatically sets ownership on `/data` using `PUID`/`PGID`).

### Step 4: Environment Variables

1. Click the **Env** tab under Advanced container settings.
2. Click **+ Add environment variable** for required settings:
   - `AUTH_EXPECTED_AUDIENCE` = `mqtt.yourdomain.com` *(or leave empty to skip audience validation)*
   - `SUBSCRIBER_1` = `viewer:password123:2`
   - `MQTT_WS_PORT` = `8883`

### Step 5: Restart Policy & Healthcheck

1. Click the **Restart policy** tab and choose **Unless stopped**.
2. Click **Deploy the container**.

---

## Verification & Logs

1. Go to **Containers** in Portainer.
2. Click the `meshcore-mqtt-broker` container name.
3. Click the **Logs** icon to inspect runtime logs. You should see output indicating the broker has started listening on port 8883.
4. Check the status indicator: it should turn **healthy** after ~10-15 seconds (probing `/health`).

---

## Automated Container Upgrades

To keep your broker automatically up to date whenever new container builds occur:

### Option 1: Portainer Webhook (Instant Automated Redeploy)

1. Open your `meshcore-mqtt-broker` Stack or Container in Portainer.
2. Scroll to **Service webhook** (or **Stack webhook**) and toggle it **ON**.
3. Copy the generated Webhook URL (e.g. `https://portainer.yourdomain.com/api/stacks/webhooks/...`).
4. Go to your GitHub repository **Settings** > **Secrets and variables** > **Actions**.
5. Create a new repository secret named `PORTAINER_WEBHOOK_URL` and paste the webhook URL.
6. Whenever GitHub Actions builds a new Docker image, GitHub will trigger Portainer to automatically pull the new image and redeploy your stack!

### Option 2: Watchtower (Automated Polling)

Include [Watchtower](https://containrrr.dev/watchtower/) in your Portainer stack to monitor `ghcr.io/dhovin/meshcore-mqtt-broker:latest` and pull updates automatically:

```yaml
  watchtower:
    image: containrrr/watchtower
    container_name: watchtower-meshcore
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --interval 3600 meshcore-mqtt-broker
```
