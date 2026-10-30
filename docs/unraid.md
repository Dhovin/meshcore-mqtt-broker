# Deploying MeshCore MQTT Broker on unRAID

This guide provides step-by-step instructions for installing and running the **MeshCore MQTT Broker** on [unRAID](https://unraid.net/).

---

## Overview

The MeshCore MQTT Broker image (`ghcr.io/dhovin/meshcore-mqtt-broker:latest`) is published as a multi-architecture container supporting both **x86_64 (`amd64`)** and **ARM64 (`arm64`)**.

You can deploy the MeshCore MQTT Broker container on unRAID in two primary ways:

1. **unRAID Docker Web GUI (Manual "Add Container")**: Recommended for standard unRAID installations using the built-in container management UI.
2. **Docker Compose Plugin (Compose Manager)**: Recommended if you prefer managing containers via `docker-compose.yml` stacks on unRAID.

---

## Method 1: Using the unRAID Docker Web GUI

### Step 1: Open the Add Container Interface

1. Log into your unRAID Web GUI.
2. Go to the **Docker** tab.
3. Scroll down and click **Add Container**.
4. In the top-right corner of the template window, toggle **Advanced View** to **ON**.

### Step 2: Configure Template Settings

Fill out the form fields with the following values:

| Field | Value | Notes |
| :--- | :--- | :--- |
| **Name** | `meshcore-mqtt-broker` | Container identifier |
| **Repository** | `ghcr.io/dhovin/meshcore-mqtt-broker:latest` | GHCR multi-arch Docker image (`amd64`/`arm64`) |
| **Icon URL** | `https://raw.githubusercontent.com/Dhovin/meshcore-mqtt-broker/main/docs/icon.png` | *(Optional)* Container icon |
| **WebUI** | `http://[IP]:[PORT:8883]/health` | Health endpoint URL (`/health` or `/healthz`) |
| **Network Type** | `Bridge` | Standard unRAID bridge network |

---

### Step 3: Add Port Mapping

Click **+ Add another Port, Variable, Line or Device**:

- **Config Type**: `Port`
- **Name**: `MQTT WebSocket Port`
- **Host Port**: `8883`
- **Container Port**: `8883`
- **Protocol**: `TCP`
- Click **Add**.

*(Optional)* If enabling plain TCP MQTT (`ENABLE_TCP_MQTT=true`) for a local Mosquitto bridge, you can also map port `1883` (TCP), restricted to your private LAN/Docker network.

---

### Step 4: Add Path / Volume Mapping (Appdata Persistence)

The container stores SQLite abuse-detection data in `/data/abuse-detection.db` and the broker's persistent Ed25519 peer keypair in `/data/peer-identity.json`. Host path mapping ensures database and public key persistence across container updates or array restarts.

Click **+ Add another Port, Variable, Line or Device**:

- **Config Type**: `Path`
- **Name**: `Appdata Directory`
- **Container Path**: `/data`
- **Host Path**: `/mnt/user/appdata/meshcore-mqtt-broker`
- **Access Mode**: `Read/Write`
- Click **Add**.

---

### Step 5: Add Environment Variables

Click **+ Add another Port, Variable, Line or Device** to create each variable required for your deployment:

1. **User / Group IDs (`PUID` & `PGID` for unRAID Appdata Permissions)**:
    - **Config Type**: `Variable` | **Name**: `PUID` | **Key**: `PUID` | **Value**: `99` *(unRAID `nobody` user)*
    - **Config Type**: `Variable` | **Name**: `PGID` | **Key**: `PGID` | **Value**: `100` *(unRAID `users` group)*

2. **Authentication Audience**:
   - **Config Type**: `Variable`
   - **Name**: `AUTH_EXPECTED_AUDIENCE`
   - **Key**: `AUTH_EXPECTED_AUDIENCE`
   - **Value**: `mqtt.yourdomain.com` *(Match your external domain or Cloudflare Tunnel endpoint, or leave empty to skip audience validation)*

3. **Default Subscriber Max Connections (Optional)**:
   - **Config Type**: `Variable`
   - **Name**: `Default Max Subscriber Connections`
   - **Key**: `SUBSCRIBER_MAX_CONNECTIONS_DEFAULT`
   - **Value**: `2`

4. **Subscriber User 1**:
   - **Config Type**: `Variable`
   - **Name**: `Subscriber 1`
   - **Key**: `SUBSCRIBER_1`
   - **Value**: `viewer1:your-secure-password:2` *(Format: `username:password:role:maxConns`, numbered sequentially from `SUBSCRIBER_1`)*

5. **Subscriber User 2 (Admin)**:
   - **Config Type**: `Variable`
   - **Name**: `Subscriber 2`
   - **Key**: `SUBSCRIBER_2`
   - **Value**: `admin:admin-password:1:10` *(Format: `username:password:role:maxConns`)*

6. **MQTT WebSocket Port (Container)**:
   - **Config Type**: `Variable`
   - **Name**: `MQTT WS Port`
   - **Key**: `MQTT_WS_PORT`
   - **Value**: `8883`

7. **HTTP Browser Redirect URL (Optional)**:
   - **Config Type**: `Variable`
   - **Name**: `HTTP Redirect URL`
   - **Key**: `HTTP_REDIRECT_URL`
   - **Value**: *(Leave blank to return 200 OK status on `/`, or set e.g. `https://yourdomain.com`. Note: `/health` and `/healthz` always return 200 OK)*

8. **Optional Standard TCP MQTT Listener (Optional)**:
   - **Config Type**: `Variable` | **Name**: `Enable TCP MQTT` | **Key**: `ENABLE_TCP_MQTT` | **Value**: `false` *(Set to `true` to enable plain TCP MQTT on `MQTT_TCP_PORT`, default `1883`)*

9. **Abuse Enforcement & Temporary Mute Timeout (Optional)**:
   - **Config Type**: `Variable`
   - **Name**: `Abuse Enforcement`
   - **Key**: `ABUSE_ENFORCEMENT_ENABLED`
   - **Value**: `false` *(Set to `true` to place offending clients in a temporary `'muted'` timeout for `ABUSE_MUTE_DURATION_MS` — default 4 hours — and silently drop their packets during the timeout)*

10. **`$SYS` Telemetry Update Interval (Optional)**:
    - **Config Type**: `Variable`
    - **Name**: `SYS Telemetry Interval (ms)`
    - **Key**: `MQTT_SYS_INTERVAL_MS`
    - **Value**: `10000` *(Updates retained `$SYS/broker/#` topics every 10 seconds for Role 1 Admin subscribers)*

11. **Peer Broker Interconnect (Optional)**:
    - **Config Type**: `Variable` | **Name**: `Authorized Inbound Peers` | **Key**: `AUTHORIZED_PEERS` | **Value**: *(Comma-separated 64-char hex Ed25519 public keys of remote peer brokers allowed to push into this broker)*
    - **Config Type**: `Variable` | **Name**: `Outbound Peer 1` | **Key**: `PEER_1` | **Value**: *(e.g. `wss://peer.yourdomain.com|peer.yourdomain.com`)*

---

### Step 6: Apply and Start

1. Review all configured ports, paths, and environment variables.
2. Click **Apply**. unRAID will download the docker image from GHCR and launch the container.

---

## Method 2: Using Docker Compose Plugin (Compose Manager)

If you have installed the **Docker Compose Plugin** (available via unRAID Community Applications):

1. Open the unRAID Web GUI and go to **Docker** > **Compose**.
2. Click **Add New Stack** and name it `meshcore-mqtt-broker`.
3. Paste the following stack definition:

```yaml
services:
  meshcore-broker:
    image: ghcr.io/dhovin/meshcore-mqtt-broker:latest
    container_name: meshcore-mqtt-broker
    restart: unless-stopped
    ports:
      - "8883:8883"
    environment:
      - PUID=99
      - PGID=100
      - MQTT_WS_PORT=8883
      - MQTT_HOST=0.0.0.0
      - AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com
      - SUBSCRIBER_1=viewer1:your-secure-password:2
      - SUBSCRIBER_2=admin:admin-password:1:10
      - LOG_LEVEL=info
      - ABUSE_ENFORCEMENT_ENABLED=false
      - ABUSE_MUTE_DURATION_MS=14400000
      - ABUSE_PERSISTENCE_PATH=/data/abuse-detection.db
    volumes:
      - /mnt/user/appdata/meshcore-mqtt-broker:/data
```

4. Click **Compose Up**.

---

## Verification & Logs

1. On the unRAID **Docker** tab, click the icon for `meshcore-mqtt-broker`.
2. Select **Logs** to open the terminal log window.
3. Confirm that the broker initializes successfully and reports listening on WebSocket port `8883`.

---

## Storage & File Permissions

The container entrypoint automatically sets ownership of `/data` to `PUID:PGID` (defaults to `1000:1000`, or `99:100` for unRAID's `nobody:users` when `PUID=99` and `PGID=100` are set) before dropping root privileges using `su-exec`.

If you run the container with a custom `--user` flag (which skips the root entrypoint `chown`), make sure the host directory is writable by that UID/GID first from the unRAID terminal:

```bash
mkdir -p /mnt/user/appdata/meshcore-mqtt-broker
chown -R 99:100 /mnt/user/appdata/meshcore-mqtt-broker
```
