# Security Audit & Hardening Documentation

This document explains the security audit findings, architectural considerations, threat models, and hardening measures implemented on the `security-hardening` branch.

---

## 1. Summary of Implemented Hardening Measures

| # | Vulnerability / Concern | Risk | Status & Mitigation |
|---|---|---|---|
| **1** | **Unbounded WebSocket `maxPayload`** | High | Configured `maxPayload: 1MB` on `WebSocketServer` to prevent memory exhaustion from giant unauthenticated frames. |
| **2** | **Vulnerable Transitive Dependencies** | High | Upgraded `ws` to `^8.20.2` and uninstalled unused `websocket-stream` (which held a vulnerable nested `ws@3.3.3`), eliminating high-severity CVEs. |
| **3** | **Unbounded Publish Size & Synchronous JSON DoS** | High | Added `MQTT_MAX_PACKET_BYTES` (default 64KB). Rejects oversized packets in `aedes.authorizePublish` before parsing JSON to prevent event-loop stalls. |
| **4** | **Proxy Header Trust in `getClientIP`** | Note | Documented: `getClientIP` trusts proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`), which is ideal behind Cloudflare Tunnels/reverse proxies. Left behavior intact. |
| **5** | **Unbounded Map in `RateLimiter`** | Medium | Bounded `failedConnectionsByIP` map to 10,000 entries (FIFO eviction) and added periodic background sweeping of expired entries to prevent OOM memory leaks. |
| **6** | **JWT Expiration & Timestamp Replay** | Medium | Added optional `AUTH_ENFORCE_EXPIRATION` setting (default `false` to preserve compatibility with offline/clockless LoRa nodes) and added sanity checks rejecting tokens dated >24h in the future. |
| **7** | **Password Comparison Timing Attacks** | Medium | Replaced `===` string comparison for subscriber passwords with `crypto.timingSafeEqual` in `src/crypto-utils.ts`. |
| **8** | **Direct Publishing to `/internal`** | Medium | Restricted `meshcore/*/*/internal` subtopics in `aedes.authorizePublish` so client devices cannot overwrite retained server telemetry and trust states. |
| **9** | **Unprotected HTTP Requests** | Low | Added `rateLimiter.isBlocked()` check to HTTP request handler, dropping requests from banned IPs before processing redirects. |
| **10** | **WebSocket Backpressure** | Low | Added `ws.pause()` when duplex stream buffers are full and `ws.resume()` on stream `drain` to prevent memory bloat during message floods. |

---

## 2. In-Depth Explanation of Each Fix

### 1 & 2. WebSocket Server Hardening & Dependency Cleanup
- **The Issue**: By default, the `ws` package allows WebSocket frames up to 100MB before closing. Furthermore, the repository listed `websocket-stream` in `package.json`, which was not used in code but pulled in an obsolete and vulnerable `ws@3.3.3` dependency.
- **The Fix**:
  - Removed unused `websocket-stream` and upgraded `ws` to `^8.20.2`.
  - Added `maxPayload: 1024 * 1024` (1MB) to `new WebSocketServer({ server: httpServer, maxPayload: 1024 * 1024 })`.
  - An unauthenticated client attempting to transmit frames larger than 1MB is immediately terminated by the WebSocket protocol layer with status 1009 (Message Too Big).

### 3. Maximum Packet Payload Limit (`MQTT_MAX_PACKET_BYTES`)
- **The Issue**: LoRa radio packets are typically ~255 bytes, and telemetry JSON payloads are rarely more than a few kilobytes. However, the broker previously accepted packets of any size and synchronously executed `JSON.parse(packet.payload.toString())`. A malicious client sending a 20MB JSON packet would freeze the single-threaded Node.js event loop for all other users.
- **The Fix**:
  - Added `MQTT_MAX_PACKET_BYTES` configuration (default 65,536 bytes / 64KB).
  - In `aedes.authorizePublish`, incoming packets exceeding this byte threshold are immediately rejected with an error before string allocation or JSON parsing occurs.

### 4. Client IP Header Trust (`getClientIP`)
- **Architectural Note**:
  - `getClientIP` reads `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` to extract the true client IP.
  - When the broker is deployed behind **Cloudflare Tunnels** or an Nginx/Caddy reverse proxy, this correctly identifies real client IPs for abuse detection and rate limiting.
  - As requested, no code changes were made to `getClientIP`. Note that if the broker is ever exposed directly to the public internet on a raw IP without a proxy, connecting clients can specify these headers.

### 5. Bounded `RateLimiter` Map & Background Sweeper
- **The Issue**: `RateLimiter` tracked failed attempts in a JavaScript `Map<string, RateLimitRecord>`. Entries were only removed if the exact same IP reconnected after the window expired. An attacker generating failed connections from thousands of spoofed or distributed IPs would cause the map to grow indefinitely, consuming RAM.
- **The Fix**:
  - Added a capacity ceiling (`maxEntries: 10000`). If exceeded, the oldest record is evicted.
  - Added a periodic background sweeper (`setInterval` with `.unref()`) every 5 minutes that removes expired failure records and unblocked IPs.
  - Added `rateLimiter.destroy()` to ensure timers are cleared on broker shutdown.

### 6. Optional JWT Expiration (`exp`) & Sanity Checks
- **The Issue**: The broker verifies Ed25519 signatures on JWTs, but did not check `exp`. Captured tokens could theoretically be replayed indefinitely. However, many LoRa mesh nodes run on embedded microcontrollers without battery-backed real-time clocks (RTC) or NTP sync, and do not feature token renewal loops.
- **The Fix**:
  - Added `AUTH_ENFORCE_EXPIRATION=false` in `.env.example`.
  - When disabled (`false`, the default), existing nodes and firmware continue functioning without disruption.
  - When enabled (`true`), tokens with an expired `exp` timestamp are rejected.
  - Added a sanity check rejecting tokens whose `iat` is more than 24 hours in the future to catch corrupted timestamps.

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
- **The Issue**: If a fast WebSocket client flooded data faster than the duplex stream or Aedes could process it, `stream.push(data)` would buffer unbounded in Node.js internal memory.
- **The Fix**:
  - Inspected the return value of `stream.push(data)`. If `false` (buffer is full), `ws.pause()` is invoked to stop reading from the socket.
  - Added a listener on `stream.on('drain')` that invokes `ws.resume()` to resume receiving once the buffer has cleared.

---

## 3. Verification

### Automated Tests
Run unit tests verifying timing-safe comparison, rate-limiter bounds, threshold blocking, and cleanup:
```bash
npm test
```

### Build Verification
Verify clean TypeScript compilation:
```bash
npm run build
```
