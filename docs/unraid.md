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
| **Icon URL** | `https://raw.githubusercontent.com/Dhovin/meshcore-mqtt-broker-docker/main/docs/icon.png` | *(Optional)* Container icon |
| **WebUI** | `http://[IP]:[PORT:8883]/` | Health endpoint URL |
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

---

### Step 4: Add Path / Volume Mapping (Appdata Persistence)

The container stores SQLite abuse-detection data in `/data/abuse-detection.db`. Host path mapping ensures database persistence across updates or array restarts.

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

1. **Authentication Audience**:
   - **Config Type**: `Variable`
   - **Name**: `AUTH_EXPECTED_AUDIENCE`
   - **Key**: `AUTH_EXPECTED_AUDIENCE`
   - **Value**: `mqtt.yourdomain.com` *(Match your external domain or Cloudflare Tunnel endpoint)*

2. **Subscriber User 1**:
   - **Config Type**: `Variable`
   - **Name**: `Subscriber 1`
   - **Key**: `SUBSCRIBER_1`
   - **Value**: `viewer1:your-secure-password:2` *(Format: `username:password:role`)*

3. **Subscriber User 2 (Admin)**:
   - **Config Type**: `Variable`
   - **Name**: `Subscriber 2`
   - **Key**: `SUBSCRIBER_2`
   - **Value**: `admin:admin-password:1:10` *(Format: `username:password:role:maxConns`)*

4. **MQTT WebSocket Port (Container)**:
   - **Config Type**: `Variable`
   - **Name**: `MQTT WS Port`
   - **Key**: `MQTT_WS_PORT`
   - **Value**: `8883`

5. **HTTP Browser Redirect URL (Optional)**:
   - **Config Type**: `Variable`
   - **Name**: `HTTP Redirect URL`
   - **Key**: `HTTP_REDIRECT_URL`
   - **Value**: *(Leave blank to return 200 OK status, or set e.g. `https://yourdomain.com`)*

6. **Abuse Enforcement (Optional)**:
   - **Config Type**: `Variable`
   - **Name**: `Abuse Enforcement`
   - **Key**: `ABUSE_ENFORCEMENT_ENABLED`
   - **Value**: `false` *(Set to `true` to enable rate limits)*

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
      - MQTT_WS_PORT=8883
      - MQTT_HOST=0.0.0.0
      - AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com
      - SUBSCRIBER_1=viewer1:your-secure-password:2
      - SUBSCRIBER_2=admin:admin-password:1:10
      - ABUSE_ENFORCEMENT_ENABLED=false
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

The container runs internally under Node.js user permissions (`node:node`) and stores files under `/mnt/user/appdata/meshcore-mqtt-broker`. Ensure that the `appdata` share has valid read/write permissions for Docker containers.
