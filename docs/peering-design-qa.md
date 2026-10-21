# Multi-Broker Peering Design: Discovery & Architecture Q&A

This document records the design interview questions, candidate options, and final decisions reached for the multi-broker forwarding feature.

---

### Question 1: Connection Architecture & Peering Relationship

**Question:** How should brokers establish connections with each other for forwarding?

**Candidate Options:**
1. *(Recommended)* Outbound MQTT/WebSocket Bridge: Each broker has a config list of remote peer broker URLs/credentials, connecting to each peer as an outbound client to push forwarded messages.
2. Inbound Peer Clients: Peer brokers connect into my broker as special authenticated "peer" clients, and my broker routes packets down those peer client connections.
3. Separate Dedicated Sync/Mesh Port: A dedicated non-MQTT sync protocol/port (e.g., HTTP/gRPC or raw WebSocket) running alongside MQTT specifically for broker-to-broker peering.

**Selected Answer / Clarification:**
> *"so i missed a step. Guy A and Guy B share data both ways. I only share data with Guy A and Guy B."*
- **Decision:** Outbound bridge connection model with directed topology. Each broker defines its outbound peer targets independently. My server pushes to Guy A and Guy B. Guy A pushes to Guy B. Guy B pushes to Guy A. Neither Guy A nor Guy B pushes to My Server.

---

### Question 2: Loop Prevention & "Unique Traffic" Definition

**Question:** What defines "unique traffic" and how should loop prevention work between brokers?

**Candidate Options:**
1. *(Recommended)* Local-only forwarding: Brokers only forward packets published directly by their own connected clients/radios, never re-forwarding packets received from other peer brokers.
2. Packet Hash Deduplication: Brokers forward all packets, but maintain a deduplication cache of packet hashes so already-seen packets are dropped before re-forwarding.
3. Broker Path Tagging: Packets carry a list of broker IDs that have processed them, so brokers never forward to peers that are already in the path.

**Selected Answer:**
> **(Recommended) Local-only forwarding: Brokers only forward packets published directly by their own connected clients/radios, never re-forwarding packets received from other peer brokers.**
- **Decision:** When a broker receives a packet from a peer broker, it delivers it to local subscribers, but flags it so it is **never** queued to outbound peers. This prevents forwarding loops between Guy A and Guy B and prevents Guy A from echoing My Server's packets to Guy B.

---

### Question 3: Peer Authentication & Origin Authorization

**Question:** How should peer brokers authenticate with each other to forward packets across different origin IDs?

**Candidate Options:**
1. *(Recommended)* Dedicated Peer Token / Shared Secret: A dedicated peer authentication method (e.g. `PEER_SECRET` or API token) in `.env` that authenticates the peer broker and authorizes it to publish packets with any `origin_id` without altering payloads.
2. Broker Ed25519 Keypair: Each broker has its own MeshCore public/private keypair; peer brokers whitelist each other's public keys in `.env` and authenticate using signed JWTs.
3. New Subscriber Role (Role 4: Peer): Extend the existing subscriber credentials system (username/password) with a new peer role that allows publishing across topics.

**Selected Answer:**
> **New Subscriber Role (Role 4: Peer): Extend the existing subscriber credentials system (username/password) with a new peer role that allows publishing across topics.**
- **Decision:** Define `SubscriberRole.PEER = 4` in subscriber credentials (`SUBSCRIBER_N=username:password:4`). Clients authenticated with Role 4 can publish to `meshcore/{IATA}/{PUBKEY}/{subtopic}` without requiring the client username to match the topic's public key or payload `origin_id`.

---

### Question 4: Disconnection & Queueing Resilience

**Question:** When an outbound peer broker is temporarily disconnected or unreachable, how should pending forwarded packets be handled?

**Candidate Options:**
1. *(Recommended)* Bounded Memory Queue with Auto-Reconnect: Auto-reconnect with backoff, buffering up to a configurable limit (e.g., 500-1000 packets) during brief outages, dropping oldest packets if the queue fills to prevent OOM.
2. Drop Immediately on Disconnect: Only forward packets when the peer connection is actively connected, never queueing during outages to ensure only live real-time traffic is sent.
3. Persistent SQLite Queue: Persist undelivered packets to an SQLite table on disk and replay them when the peer comes back online.

**Selected Answer:**
> **(Recommended) Bounded Memory Queue with Auto-Reconnect: Auto-reconnect with backoff, buffering up to a configurable limit (e.g., 500-1000 packets) during brief outages, dropping oldest packets if the queue fills to prevent OOM.**
- **Decision:** Peer bridges maintain an in-memory FIFO queue bounded by `PEER_QUEUE_MAX_SIZE` (default 1000). While disconnected, auto-reconnect runs with backoff. If the queue overflows, the oldest packet is dropped. When connection succeeds, the queue is drained in order.

---

### Question 5: Topic Scope for Forwarding

**Question:** Which topics and message types should be forwarded to peer brokers?

**Candidate Options:**
1. *(Recommended)* Forward both packets and status (`meshcore/*/{packets,status}`): Forward both radio packets and node status messages intact (unfiltered), while excluding internal PII and serial commands.
2. Forward packets only (`meshcore/*/packets`): Only forward radio packet traffic, ignoring status and all other subtopics.
3. Configurable topic filter per peer: Allow configuring a whitelist of subtopic patterns per peer in the environment settings (e.g., `PEER_1_TOPICS=packets,status`).

**Selected Answer:**
> **option 1 but also include neighbors and raw**
- **Decision:** Forwarded subtopics are `packets`, `status`, `neighbors`, and `raw`. Sensitive/internal topics (`/internal`, `/serial/*`, `$SYS/*`) are strictly excluded from forwarding.

---

### Question 6: Configuration Format for Outbound Peers

**Question:** How would you prefer to configure outbound peer targets in `.env`?

**Candidate Options:**
1. *(Recommended)* Compact delimiter format: `PEER_1=ws://guy-a.example.com:8883:username:password` (matching the existing `SUBSCRIBER_N` pattern).
2. Multi-variable format: `PEER_1_URL=...`, `PEER_1_USERNAME=...`, `PEER_1_PASSWORD=...` (cleaner for complex URLs or special characters).
3. JSON array format: `PEERS=[{"url":"ws://...","username":"...","password":"..."}]` in a single environment variable.

**Selected Answer:**
> **(Recommended) Compact delimiter format: PEER_1=ws://guy-a.example.com:8883:username:password (matching the existing SUBSCRIBER_N pattern).**
- **Decision:** Support indexed `PEER_1`, `PEER_2`, ... in `.env` using `url:username:password`, with parsing supporting URLs containing colons and paths.

---

### Question 7: Abuse Detection Enforcement on Peer Traffic

**Question:** How should incoming packets from authenticated peer brokers be handled by the abuse detector?

**Candidate Options:**
1. *(Recommended)* Bypass abuse detector for peer traffic: Packets arriving from authenticated peer brokers bypass the token bucket, rate limits, and anomaly muting, since they are already validated by the originating broker.
2. Track origin_id in abuse detector without muting peer: Track stats per origin_id for metrics/monitoring, but never mute or disconnect the peer connection.
3. Apply full abuse detection to peer: Enforce all rate limits and duplicate checks on peer connections just like direct clients.

**Selected Answer:**
> **Apply full abuse detection to peer: Enforce all rate limits and duplicate checks on peer connections just like direct clients.**
- **Decision:** Incoming peer packets are evaluated by the abuse detector using the packet's `origin_id`. If an individual origin node is anomalous or rate-limited, only that origin node's packets are silenced, while the peer connection remains operational.
