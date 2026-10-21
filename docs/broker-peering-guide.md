# Multi-Broker Peering & Packet Forwarding Guide

This guide explains how to connect multiple `meshcore-mqtt-broker` instances together to share MeshCore packet traffic across different servers and regions, while preventing duplicate messages and routing loops.

---

## 1. What It Does

When running multiple MeshCore MQTT brokers, you may want them to exchange radio and telemetry traffic with partner brokers. 

### Key Characteristics
- **Push-Based WebSocket Bridging**: A broker connects out to remote peer brokers over WebSocket MQTT (`ws://` or `wss://`), pushing forwarded packets directly.
- **Local-Only Forwarding (Loop Prevention)**: A broker only forwards packets that originated from its own locally connected mesh clients/radios. Packets received from a peer broker are delivered to local subscribers, but are **never re-forwarded** to other peers.
- **Preserved Origins**: Packets are delivered with the original node's public key, IATA location, SNR, RSSI, and payload intact.
- **Per-Origin Abuse Enforcement**: If a radio node on a peer broker sends abusive traffic, only that individual origin node is muted—the peer connection itself remains online.
- **Offline Bounded Queues**: If a remote peer broker restarts or is temporarily offline, packets buffer in a bounded FIFO queue and automatically drain upon reconnection. If the queue fills, the oldest packets are safely dropped to prevent memory exhaustion.

---

## 2. The 3-Step Setup Process

Setting up forwarding between two brokers (Broker A and Broker B) requires just two configuration changes:
1. **On the receiving broker**: Add a **Subscriber Role 4 (Peer)** credential in `.env`.
2. **On the sending broker**: Add an outbound **`PEER_N`** target in `.env`.

```mermaid
sequenceDiagram
    autonumber
    participant Radio as Local Radio / Node
    participant BrokerA as Broker A (Sender)
    participant BrokerB as Broker B (Receiver)
    participant Viewer as Broker B Subscribers

    Radio->>BrokerA: Publishes local packet (v1_PUBKEY)
    BrokerA->>BrokerA: Delivers locally to Broker A subscribers
    BrokerA->>BrokerB: Pushes packet via Outbound Bridge (PEER_1)
    BrokerB->>BrokerB: Authenticates as Role 4 (Peer) & tags fromPeer=true
    BrokerB->>Viewer: Delivers packet to Broker B subscribers
    Note over BrokerB: Packet is NOT forwarded to other peers (No Loops)
```

---

## 3. Step-by-Step Instructions

### Step 1: Create a Peer Account on the Receiving Broker

On the broker that will **receive** traffic, add an inbound subscriber account with **Role 4** to `.env`:

```bash
# Format: SUBSCRIBER_N=username:password:role:maxConnections
# Role 4 grants peer bridge privileges (allows publishing across all origin node keys)
SUBSCRIBER_4=peer_from_brokera:SuperSecretPassword123:4
```

> [!NOTE]
> Role 4 accounts can only publish to valid meshcore traffic topics (`packets`, `status`, `neighbors`, `raw`). They cannot publish to administrative `/internal` topics or remote serial consoles.

Restart the receiving broker to load the new credentials.

---

### Step 2: Configure the Outbound Bridge on the Sending Broker

On the broker that will **send** traffic, add the remote broker's URL and credentials to `.env`:

```bash
# Format: PEER_N=URL:username:password
# Supported schemes: ws:// or wss://
PEER_1=wss://broker-b.yourdomain.com:peer_from_brokera:SuperSecretPassword123

# Optional: Maximum queued packets during disconnections (default: 1000)
PEER_QUEUE_MAX_SIZE=1000
```

> [!TIP]
> If your remote broker is behind Cloudflare Tunnels or SSL, use `wss://` (port 443 by default). If running directly on a private IP, use `ws://192.168.1.50:8883`.

Restart the sending broker. In the console logs, you will see:
```text
[CONFIG] Loaded outbound peer: peer_1 -> wss://broker-b.yourdomain.com (user: peer_from_brokera)
[PEER_BRIDGE] Initializing 1 outbound peer bridge(s) (queue limit: 1000)
[PEER:peer_1] Connecting to wss://broker-b.yourdomain.com as "peer_from_brokera"...
[PEER:peer_1] ✓ Connected to peer at wss://broker-b.yourdomain.com
```

---

## 4. Real-World Walkthrough: You + Guy A + Guy B

In this scenario:
- **You (My Server)** forward your local mesh traffic to **Guy A** and **Guy B**.
- **Guy A** and **Guy B** share traffic bidirectionally with each other (**Guy A <-> Guy B**).
- Neither Guy A nor Guy B forwards traffic back to **You**.
- Guy A does **not** duplicate your traffic when sharing with Guy B.

```mermaid
flowchart LR
    subgraph MyServer ["My Server (You)"]
        MyBroker["Local Broker"]
    end

    subgraph GuyAServer ["Guy A Server"]
        GuyABroker["Local Broker"]
    end

    subgraph GuyBServer ["Guy B Server"]
        GuyBBroker["Local Broker"]
    end

    MyBroker -->|"PEER_1"| GuyABroker
    MyBroker -->|"PEER_2"| GuyBBroker
    GuyABroker <-->|"PEER_1 <--> PEER_1"| GuyBBroker
```

### Server Configuration Summary

| Server | Inbound Accounts Needed (`SUBSCRIBER_N`) | Outbound Peers Needed (`PEER_N`) |
| :--- | :--- | :--- |
| **My Server** | *(None needed for peers, since neither Guy A nor B pushes to you)* | `PEER_1=wss://guya.com:my_peer:passA`<br>`PEER_2=wss://guyb.com:my_peer:passB` |
| **Guy A** | `SUBSCRIBER_4=my_peer:passA:4`<br>`SUBSCRIBER_5=guy_b_peer:passBtoA:4` | `PEER_1=wss://guyb.com:guy_a_peer:passAtoB` |
| **Guy B** | `SUBSCRIBER_4=my_peer:passB:4`<br>`SUBSCRIBER_5=guy_a_peer:passAtoB:4` | `PEER_1=wss://guya.com:guy_b_peer:passBtoA` |

### Why Routing Loops Cannot Happen
1. When you publish packet $P_1$, it is forwarded to Guy A and Guy B.
2. When Guy A receives $P_1$, Guy A tags it as `fromPeer = true`.
3. When Guy A checks its outbound queue to Guy B, it sees $P_1$ was received from a peer, so it **does not** send $P_1$ to Guy B. Guy B only receives $P_1$ once (directly from you).
4. When Guy A generates a local packet $P_A$, Guy A forwards it to Guy B. Guy B delivers $P_A$ locally, but does not send it back to Guy A or to You.

---

## 5. Forwarded Topics & Payload Scope

### Forwarded Subtopics
- `meshcore/{IATA}/{PUBKEY}/packets` — LoRa radio packets, SNR, RSSI
- `meshcore/{IATA}/{PUBKEY}/status` — Node status, battery, telemetry
- `meshcore/{IATA}/{PUBKEY}/neighbors` — Neighbor node lists
- `meshcore/{IATA}/{PUBKEY}/raw` — Raw payload streams

### Filtered / Excluded Subtopics
- `meshcore/{IATA}/{PUBKEY}/internal` — **Blocked** (admin JWTs, trust metrics, client IPs)
- `meshcore/{IATA}/{PUBKEY}/serial/*` — **Blocked** (remote serial console commands and responses)
- `$SYS/*` — **Blocked** (internal broker stats)

---

## 6. Monitoring & Troubleshooting

### Log Prefixes
- `[PEER:peer_1]` — Outbound bridge client activity (connecting, queueing, forwarding).
- `[P:username]` — Inbound peer connection activity (authenticated peer publishing).
- `[O:pubkey]` — Local radio publisher connection.
- `[S:username]` — Standard subscriber connection.

### Common Issues

#### 1. Peer Connection Fails: `[ERROR] connect ECONNREFUSED`
- **Cause**: Remote broker is offline, host/port is wrong, or firewall is blocking the port.
- **Fix**: Verify the remote broker is running and accessible via browser or `curl`. Packets will safely buffer in the queue up to `PEER_QUEUE_MAX_SIZE`.

#### 2. Peer Publish Denied: `[AUTHZ] ✗ Peer publish denied (subtopic "internal" not allowed)`
- **Cause**: A client attempted to forward an administrative or non-whitelisted topic.
- **Fix**: Only traffic on `packets`, `status`, `neighbors`, and `raw` is permitted. Internal topics containing PII are intentionally protected.

#### 3. Subscriber Role Denied: `[AUTHZ] ✗ Publish denied (subscriber)`
- **Cause**: The inbound account on the receiving broker was configured with Role 1, 2, or 3 instead of Role 4.
- **Fix**: Ensure the receiving broker's `.env` specifies `:4` at the end:
  ```env
  SUBSCRIBER_N=username:password:4
  ```
