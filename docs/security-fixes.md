# Security Audit & Hardening Documentation

This document explains the security audit findings, architectural considerations, threat models, and hardening measures implemented on the `security-hardening` branch.

---

## 1. Summary of Implemented Hardening Measures

| # | Vulnerability / Concern | Risk | Status & Mitigation |
|---|---|---|---|
| **1** | **Unbounded WebSocket `maxPayload`** | High | Configured `maxPayload: 1MB` on `WebSocketServer` to prevent memory exhaustion from giant unauthenticated frames. |
| **2** | **Vulnerable Transitive Dependencies** | High | Upgraded `ws` to `^8.22.0` and uninstalled unused `websocket-stream` (which held a vulnerable nested `ws@3.3.3`), eliminating high-severity CVEs. |
| **3** | **Unbounded Packet Parsing & Memory Exhaustion** | High | Implemented streaming MQTT remaining-length validation in `ws.on('message')` via `MqttStreamValidator` to drop oversized packets before Aedes buffers them, plus `MQTT_MAX_PACKET_BYTES` (default 64KB) check in `aedes.authorizePublish`. |
| **4** | **Proxy Header Trust in `getClientIP`** | Note | Documented: `getClientIP` trusts proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`), which is ideal behind Cloudflare Tunnels/reverse proxies. Left behavior intact. |
| **5** | **Rate-Limiter Eviction & Memory Bounds** | Medium | Bounded `failedConnectionsByIP` map to 10,000 entries with prioritized eviction (expired first, then unblocked LRU; active blocks are never evicted to prevent spoofing bypasses), plus periodic background sweeping. |
| **6** | **JWT Authentication & Node Clocks** | Medium | Relies on `@michaelhart/meshcore-decoder`'s built-in `exp` enforcement when present. Hardware tokens without `exp` remain supported for offline/clockless nodes. Avoided premature future `iat` lockouts for nodes with drifted clocks. |
| **7** | **Password Comparison Timing Attacks** | Medium | Replaced `===` string comparison for subscriber passwords with `crypto.timingSafeEqual` in `src/crypto-utils.ts`. |
| **8** | **Direct Publishing to `/internal`** | Medium | Restricted `meshcore/*/*/internal` subtopics in `aedes.authorizePublish` so client devices cannot overwrite retained server telemetry and trust states. |
| **9** | **Unprotected HTTP Requests** | Low | Added `rateLimiter.isBlocked()` check to HTTP request handler, dropping requests from banned IPs before processing redirects. |
| **10** | **WebSocket Backpressure** | High | Implemented bidirectional backpressure: `ws.pause()` when readable duplex buffer is full (`stream.push(data) === false`), and `ws.resume()` triggered in `Duplex.read()` when consumer reads data. |

---

## 2. In-Depth Explanation of Each Fix

### 1 & 2. WebSocket Server Hardening & Dependency Cleanup
- **The Issue**: By default, the `ws` package allows WebSocket frames up to 100MB before closing. Furthermore, the repository listed `websocket-stream` in `package.json`, which was not used in code but pulled in an obsolete and vulnerable `ws@3.3.3` dependency.
- **The Fix**:
  - Removed unused `websocket-stream` and upgraded `ws` to `^8.22.0`.
  - Added `maxPayload: 1024 * 1024` (1MB) to `new WebSocketServer({ server: httpServer, maxPayload: 1024 * 1024 })`.
  - An unauthenticated client attempting to transmit individual frames larger than 1MB is immediately terminated by the WebSocket protocol layer with status 1009 (Message Too Big).

### 3. Maximum Packet Payload Limit & Stream Validation (`MQTT_MAX_PACKET_BYTES`)
- **The Issue**: Aedes 0.51 parses MQTT streams using `mqtt.parser()` which buffers the entire MQTT packet in memory (up to 256MB) before emitting it. A client could send multi-megabyte packets across multiple small WebSocket frames or prior to authentication, exhausting broker RAM. In addition, synchronous `JSON.parse` of giant payloads would stall the single-threaded Node.js event loop.
- **The Fix**:
  - Created `MqttStreamValidator` (`src/mqtt-packet-validator.ts`) which validates MQTT packet remaining-length headers at the WebSocket stream boundary (`ws.on('message')`).
  - As byte chunks arrive from the socket, the validator decodes the MQTT variable-byte remaining-length field. If any packet declares a remaining length exceeding `maxPacketBytes + 4096` (headroom for topic/headers) or provides malformed length bytes (> 4 continuation bytes), the connection is immediately terminated (`ws.terminate()` and `stream.destroy()`).
  - In `aedes.authorizePublish`, payload length is strictly validated against `mqttConfig.maxPacketBytes` (default 64KB) before JSON parsing occurs.

### 4. Client IP Header Trust (`getClientIP`)
- **Architectural Note**:
  - `getClientIP` reads `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` to extract the true client IP.
  - When the broker is deployed behind **Cloudflare Tunnels** or an Nginx/Caddy reverse proxy, this correctly identifies real client IPs for abuse detection and rate limiting.
  - As requested, no code changes were made to `getClientIP`. Note that if the broker is ever exposed directly to the public internet on a raw IP without a proxy, connecting clients can specify these headers.

### 5. Bounded `RateLimiter` Map & Secure Eviction
- **The Issue**: An attacker generating failed connections from thousands of spoofed or distributed IPs could cause the rate limiter map to grow indefinitely. Furthermore, simple FIFO eviction would evict the oldest entries first—which are often the ones currently blocked—enabling an attacker to unblock themselves by flooding with spoofed IPs.
- **The Fix**:
  - Added a capacity ceiling (`maxEntries: 10000`).
  - Implemented prioritized eviction (`evictEntry`):
    1. Evicts expired failure records first.
    2. Evicts the oldest unblocked failure record second.
    3. Active blocks are **never** evicted just to make room for new records.
  - Added a periodic background sweeper (`setInterval` with `.unref()`) every 5 minutes that removes expired records.
  - Added `rateLimiter.destroy()` to ensure timers are cleared on broker shutdown.

### 6. JWT Authentication & Clock Handling
- **The Issue**: LoRa mesh nodes often run on embedded microcontrollers without battery-backed real-time clocks (RTC) or NTP sync, and token issuer clocks can drift into the future.
- **The Implementation**:
  - The broker uses `@michaelhart/meshcore-decoder`'s `verifyAuthToken`. The decoder library already validates Ed25519 cryptographic signatures and automatically enforces token expiration (`exp`) whenever present.
  - Publisher tokens for clockless/offline hardware omit `exp` (as documented in `README.md`) and remain valid indefinitely.
  - Avoided arbitrary future `iat` rejection thresholds that could lock out genuine nodes whose unsynchronized clocks run ahead.

### 7. Timing-Safe Password Comparison
- **The Issue**: Standard string comparison (`password === expectedPassword`) short-circuits on the first mismatched character. By measuring subtle response latency differences across thousands of requests, attackers can incrementally deduce valid characters.
- **The Fix**:
  - Created `src/crypto-utils.ts` exporting `timingSafeCompare()`.
  - Uses Node.js's built-in `crypto.timingSafeEqual` comparing UTF-8 buffers in constant time regardless of where or whether characters match.

### 8. Protecting the `/internal` Topic
- **The Issue**: When publishers connect, the broker generates a private administrative telemetry report containing trust states and decoded JWT info and publishes it to `meshcore/{IATA}/{PUBKEY}/internal`. However, the broker's publish authorization previously allowed publishers to publish to any subtopic, meaning a rogue publisher could publish to `/internal` and overwrite the broker's genuine telemetry report.
- **The Fix**:
  - In `aedes.authorizePublish`, explicitly reject publishes where `subtopic === 'internal'`.
  - Only the broker's internal logic can publish to `/internal`. Client login authentication via JWT is completely unaffected.

### 9. Rate Limiting HTTP Server Requests
- **The Issue**: Non-WebSocket HTTP requests to the broker are redirected to `https://analyzer.letsmesh.net/`. However, `rateLimiter.isBlocked()` was only checked on WebSocket upgrades, allowing banned IPs to flood plain HTTP requests.
- **The Fix**:
  - In `httpServer`'s request listener, `rateLimiter.isBlocked(clientIP)` is evaluated immediately. If blocked, the socket is destroyed without sending redirects.

### 10. WebSocket Backpressure Handling
- **The Issue**: In Node.js Duplex streams, backpressure on the readable side (incoming data from WebSocket to broker) is signaled by `stream.push(chunk) === false`. The stream asks for more incoming data by invoking `Duplex.read()` when the consumer pulls data out of the readable buffer. Relying on the `'drain'` event causes a permanent freeze because `'drain'` is only emitted on the writable side (outgoing data sent from broker to client).
- **The Fix**:
  - When `stream.push(data)` returns `false`, `ws.pause()` is called to pause reading frames from the WebSocket.
  - Inside the Duplex's `read()` method, `ws.resume()` is called when the consumer is ready for more data.
  - The erroneous `'drain'` listener was removed.

---

## 3. Verification

### Automated Tests
Run unit tests verifying timing-safe comparison, rate-limiter bounds, threshold blocking, secure eviction, MQTT stream parsing, and backpressure:
```bash
npm test
```

### Build Verification
Verify clean TypeScript compilation:
```bash
npm run build
```
