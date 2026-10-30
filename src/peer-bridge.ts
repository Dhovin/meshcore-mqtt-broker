import WebSocket from 'ws';
import mqttPacket from 'mqtt-packet';
import crypto from 'crypto';
import { PeerConfig, PeerTarget } from './config.js';
import { PeerKeyPair, createPeerJwt } from './peer-crypto.js';

export interface QueueItem {
  topic: string;
  payload: Buffer;
  qos: 0 | 1;
  retain: boolean;
  enqueuedAt: number;
  byteSize: number;
}

export interface PeerState {
  target: PeerTarget;
  ws: WebSocket | null;
  connected: boolean;
  draining: boolean;
  queue: QueueItem[];
  queuedBytes: number;
  totalForwarded: number;
  totalDropped: number;
  reconnectAttempts: number;
  reconnectTimer?: NodeJS.Timeout;
  keepaliveTimer?: NodeJS.Timeout;
  tokenRefreshTimer?: NodeJS.Timeout;
  awaitingPingresp: boolean;
}

// Subtopics allowed for broker-to-broker forwarding
export const ALLOWED_PEER_SUBTOPICS = ['packets', 'status', 'neighbors', 'raw'];

// Maximum WebSocket buffered bytes before pausing drain slice
const MAX_WS_BUFFERED_BYTES = 512 * 1024;
// Number of packets to drain per event-loop turn
const DRAIN_BATCH_SLICE = 32;
// Keepalive interval (25s keeps Cloudflare Tunnels and NAT sessions open)
const KEEPALIVE_INTERVAL_MS = 25000;
// Cooldown when upstream explicitly refuses authentication
const AUTH_REFUSED_BACKOFF_MS = 300000;

// Validate if topic matches meshcore/{IATA}/{PUBLIC_KEY}/{subtopic} where subtopic is allowed
export function isForwardableTopic(topic: string): boolean {
  if (!topic || !topic.startsWith('meshcore/')) {
    return false;
  }

  const parts = topic.split('/').map(part => part.trim());
  if (parts.length < 4) {
    return false;
  }

  // Reject internal or serial topics
  if (topic.includes('/internal') || topic.includes('/serial/')) {
    return false;
  }

  const subtopic = parts.slice(3).join('/');
  return ALLOWED_PEER_SUBTOPICS.includes(subtopic);
}

export interface PeerValidationResult {
  valid: boolean;
  error?: string;
  normalizedTopic?: string;
  originId?: string;
  normalizedLocation?: string;
  subtopic?: string;
  parsedMessage?: any;
}

// Validate inbound packet published by a peer broker
export function validatePeerPacket(
  topic: string,
  payload: Buffer | string,
  isValidIata: (code: string) => boolean = () => true
): PeerValidationResult {
  if (!topic || !topic.startsWith('meshcore/')) {
    return { valid: false, error: 'Peer publish must start with meshcore/' };
  }

  const topicParts = topic.split('/').map(part => part.trim());
  if (topicParts.length < 4) {
    return { valid: false, error: 'Topic must be meshcore/IATA/PUBKEY/subtopic format (4 parts required)' };
  }

  const subtopic = topicParts.slice(3).join('/');
  if (!ALLOWED_PEER_SUBTOPICS.includes(subtopic)) {
    return { valid: false, error: `Peer forwarding only allows subtopics: ${ALLOWED_PEER_SUBTOPICS.join(', ')}` };
  }

  const locationCode = topicParts[1].trim();
  if (locationCode.toUpperCase() === 'XXX') {
    return { valid: false, error: 'XXX is not a valid location code' };
  }

  const isTestRegion = locationCode.toLowerCase() === 'test';
  const iataRegex = /^[A-Z]{3}$/;
  const upperLocation = locationCode.toUpperCase();
  if (!isTestRegion) {
    if (!iataRegex.test(upperLocation) || !isValidIata(upperLocation)) {
      return { valid: false, error: 'Location must be a valid IATA international airport code or "test"' };
    }
  }

  const topicPublicKey = topicParts[2].trim().toUpperCase();
  if (!/^[0-9A-F]{64}$/i.test(topicPublicKey)) {
    return { valid: false, error: 'Public key in topic must be 64 hex characters' };
  }

  try {
    const payloadStr = Buffer.isBuffer(payload) ? payload.toString('utf-8') : payload;
    const message = JSON.parse(payloadStr);

    if (!message.origin_id || !/^[0-9A-F]{64}$/i.test(message.origin_id.toString().trim())) {
      return { valid: false, error: 'Message payload must contain valid 64-hex origin_id' };
    }

    const originId = message.origin_id.toString().trim().toUpperCase();
    if (originId !== topicPublicKey) {
      return { valid: false, error: 'origin_id in payload must match public key in topic' };
    }

    const normalizedLocation = isTestRegion ? 'test' : locationCode.toUpperCase();
    const normalizedTopic = `meshcore/${normalizedLocation}/${topicPublicKey}/${subtopic}`;

    return {
      valid: true,
      normalizedTopic,
      originId,
      normalizedLocation,
      subtopic,
      parsedMessage: message,
    };
  } catch {
    return { valid: false, error: 'Invalid JSON payload in peer packet' };
  }
}

export class PeerBridgeManager {
  private peers: Map<string, PeerState> = new Map();
  private maxQueueSize: number;
  private maxQueueBytes: number;
  private queueTtlMs: number;
  private identity?: PeerKeyPair;
  private shuttingDown: boolean = false;
  private debugLog: boolean;

  constructor(config: PeerConfig, identity?: PeerKeyPair, debugLog: boolean = false) {
    this.maxQueueSize = config.maxQueueSize || 5000;
    this.maxQueueBytes = config.maxQueueBytes || 8388608; // 8 MiB default
    this.queueTtlMs = config.queueTtlMs || 600000;        // 10 min default
    this.identity = identity;
    this.debugLog = debugLog;

    if (!config.peers || config.peers.length === 0) {
      console.log('[PEER_BRIDGE] No outbound peer brokers configured');
      return;
    }

    console.log(
      `[PEER_BRIDGE] Initializing ${config.peers.length} outbound peer bridge(s) (queue limit: ${this.maxQueueSize} pkts / ${Math.round(this.maxQueueBytes / 1048576)} MiB, TTL: ${Math.round(this.queueTtlMs / 1000)}s)`
    );

    for (const target of config.peers) {
      const peerState: PeerState = {
        target,
        ws: null,
        connected: false,
        draining: false,
        queue: [],
        queuedBytes: 0,
        totalForwarded: 0,
        totalDropped: 0,
        reconnectAttempts: 0,
        awaitingPingresp: false,
      };
      this.peers.set(target.id, peerState);
      void this.connectPeer(peerState);
    }
  }

  private clearPeerTimers(peerState: PeerState): void {
    if (peerState.keepaliveTimer) {
      clearInterval(peerState.keepaliveTimer);
      peerState.keepaliveTimer = undefined;
    }
    if (peerState.tokenRefreshTimer) {
      clearInterval(peerState.tokenRefreshTimer);
      peerState.tokenRefreshTimer = undefined;
    }
  }

  private scheduleReconnect(peerState: PeerState, overrideDelayMs?: number): void {
    if (this.shuttingDown || peerState.reconnectTimer) {
      return;
    }

    let delayMs: number;
    if (overrideDelayMs !== undefined) {
      delayMs = overrideDelayMs;
    } else {
      const exp = Math.min(peerState.reconnectAttempts, 6);
      const base = Math.min(60000, 1000 * Math.pow(2, exp));
      delayMs = Math.round(base * (0.75 + 0.5 * Math.random()));
    }
    peerState.reconnectAttempts++;

    peerState.reconnectTimer = setTimeout(() => {
      peerState.reconnectTimer = undefined;
      void this.connectPeer(peerState);
    }, delayMs);

    if (peerState.reconnectTimer.unref) {
      peerState.reconnectTimer.unref();
    }
  }

  private async connectPeer(peerState: PeerState): Promise<void> {
    if (this.shuttingDown) {
      return;
    }

    const { target } = peerState;
    const logPrefix = `[PEER:${target.id}]`;

    let username: string;
    let password: string;

    try {
      if (target.username && target.password) {
        username = target.username;
        password = target.password;
      } else if (this.identity && target.targetAudience) {
        username = `v1_${this.identity.publicKeyHex}`;
        // Always mint a fresh token right before opening the socket
        password = await createPeerJwt(this.identity, target.targetAudience, 86400);
      } else {
        console.error(`${logPrefix} Missing peer identity or credentials for ${target.url}`);
        return;
      }
    } catch (err: any) {
      console.error(`${logPrefix} Failed to generate peer JWT: ${err.message}`);
      this.scheduleReconnect(peerState);
      return;
    }

    if (this.shuttingDown) {
      return;
    }

    let ws: WebSocket;
    try {
      ws = new WebSocket(target.url, ['mqtt'], {
        handshakeTimeout: 10000,
        perMessageDeflate: false,
      });
    } catch (err: any) {
      console.error(`${logPrefix} Failed to create WebSocket for ${target.url}: ${err.message}`);
      this.scheduleReconnect(peerState);
      return;
    }

    peerState.ws = ws;
    const parser = mqttPacket.parser({ protocolVersion: 4 });
    let authRefused = false;

    parser.on('packet', (packet: any) => {
      if (this.shuttingDown || peerState.ws !== ws) return;

      if (packet.cmd === 'connack') {
        if (packet.returnCode === 0) {
          peerState.connected = true;
          peerState.reconnectAttempts = 0;
          peerState.awaitingPingresp = false;
          console.log(`${logPrefix} ✓ Connected to peer at ${target.url}`);

          this.clearPeerTimers(peerState);

          // Send MQTT PINGREQ every 25s to keep WebSocket/Cloudflare Tunnel alive
          peerState.keepaliveTimer = setInterval(() => {
            if (!peerState.connected || peerState.ws !== ws || ws.readyState !== WebSocket.OPEN) {
              return;
            }
            if (peerState.awaitingPingresp) {
              console.warn(`${logPrefix} Keepalive PINGRESP timeout, reconnecting...`);
              ws.terminate();
              return;
            }
            peerState.awaitingPingresp = true;
            const pingBuf = mqttPacket.generate({ cmd: 'pingreq' });
            ws.send(pingBuf, () => {});
          }, KEEPALIVE_INTERVAL_MS);
          if (peerState.keepaliveTimer.unref) {
            peerState.keepaliveTimer.unref();
          }

          // Proactively rotate the 24h JWT every 12h by cycling the connection cleanly
          if (this.identity && !target.username) {
            peerState.tokenRefreshTimer = setInterval(() => {
              if (!this.shuttingDown && peerState.ws === ws) {
                console.log(`${logPrefix} Rotating 12h peer JWT token...`);
                ws.close();
              }
            }, 12 * 60 * 60 * 1000);
            if (peerState.tokenRefreshTimer.unref) {
              peerState.tokenRefreshTimer.unref();
            }
          }

          this.drainQueue(peerState);
        } else {
          authRefused = true;
          console.error(
            `${logPrefix} ✗ Upstream refused MQTT CONNECT (returnCode: ${packet.returnCode}) — pausing retries for ${AUTH_REFUSED_BACKOFF_MS / 60000}m`
          );
          ws.close();
        }
      } else if (packet.cmd === 'pingresp') {
        peerState.awaitingPingresp = false;
      }
    });

    parser.on('error', (err: Error) => {
      if (!this.shuttingDown) {
        console.error(`${logPrefix} MQTT parser error: ${err.message}`);
      }
    });

    ws.on('open', () => {
      if (this.shuttingDown || peerState.ws !== ws) {
        ws.close();
        return;
      }

      const suffix = this.identity
        ? this.identity.publicKeyHex.substring(0, 8)
        : crypto.randomBytes(4).toString('hex');

      const connectBuf = mqttPacket.generate({
        cmd: 'connect',
        protocolId: 'MQTT',
        protocolVersion: 4,
        clean: true,
        keepalive: 30,
        clientId: `peer_${target.id}_${suffix}`,
        username,
        password: Buffer.from(password, 'utf-8'),
      });

      ws.send(connectBuf, (err) => {
        if (err && !this.shuttingDown) {
          console.error(`${logPrefix} Failed to send CONNECT packet: ${err.message}`);
        }
      });
    });

    ws.on('message', (data: WebSocket.RawData) => {
      if (this.shuttingDown || peerState.ws !== ws) return;
      const buf = Buffer.isBuffer(data)
        ? data
        : Array.isArray(data)
          ? Buffer.concat(data)
          : Buffer.from(data);
      parser.parse(buf);
    });

    ws.on('unexpected-response', (_req, res) => {
      const code = res.statusCode || 0;
      if (code === 401 || code === 403 || code === 429 || code === 508) {
        authRefused = true;
        console.error(`${logPrefix} ✗ Upstream HTTP ${code} on WebSocket upgrade — pausing retries for ${AUTH_REFUSED_BACKOFF_MS / 60000}m`);
      }
      res.resume();
    });

    ws.on('error', (err: Error) => {
      if (!this.shuttingDown && peerState.connected) {
        console.error(`${logPrefix} [ERROR] ${err.message}`);
      }
    });

    ws.on('close', () => {
      if (peerState.ws !== ws) return;
      const wasConnected = peerState.connected;
      peerState.connected = false;
      peerState.draining = false;
      peerState.ws = null;
      this.clearPeerTimers(peerState);

      if (!this.shuttingDown) {
        if (wasConnected) {
          console.log(`${logPrefix} ✗ Connection closed (buffered packets: ${peerState.queue.length})`);
        }
        this.scheduleReconnect(peerState, authRefused ? AUTH_REFUSED_BACKOFF_MS : undefined);
      }
    });
  }

  /**
   * Prune expired items exceeding queueTtlMs from the front of the queue.
   */
  private pruneExpiredQueue(peerState: PeerState, now: number = Date.now()): void {
    while (peerState.queue.length > 0 && now - peerState.queue[0].enqueuedAt > this.queueTtlMs) {
      const expired = peerState.queue.shift()!;
      peerState.queuedBytes = Math.max(0, peerState.queuedBytes - expired.byteSize);
      peerState.totalDropped++;
    }
  }

  /**
   * Drain queued packets in asynchronous slices via setImmediate while respecting ws.bufferedAmount.
   */
  private drainQueue(peerState: PeerState): void {
    if (peerState.draining || !peerState.connected || !peerState.ws || peerState.queue.length === 0) {
      return;
    }

    const logPrefix = `[PEER:${peerState.target.id}]`;
    this.pruneExpiredQueue(peerState);
    if (peerState.queue.length === 0) {
      return;
    }

    peerState.draining = true;
    console.log(`${logPrefix} Draining ${peerState.queue.length} queued packet(s) (${peerState.queuedBytes} bytes)...`);

    const drainSlice = () => {
      if (
        this.shuttingDown ||
        !peerState.connected ||
        !peerState.ws ||
        peerState.ws.readyState !== WebSocket.OPEN
      ) {
        peerState.draining = false;
        return;
      }

      this.pruneExpiredQueue(peerState);

      // Pause if WebSocket outgoing buffer is full
      if (peerState.ws.bufferedAmount > MAX_WS_BUFFERED_BYTES) {
        const retryTimer = setTimeout(drainSlice, 25);
        if (retryTimer.unref) retryTimer.unref();
        return;
      }

      let sentInSlice = 0;
      while (
        peerState.queue.length > 0 &&
        sentInSlice < DRAIN_BATCH_SLICE &&
        peerState.ws.bufferedAmount <= MAX_WS_BUFFERED_BYTES
      ) {
        const item = peerState.queue.shift()!;
        peerState.queuedBytes = Math.max(0, peerState.queuedBytes - item.byteSize);
        this.sendPublishFrame(peerState, item.topic, item.payload);
        sentInSlice++;
      }

      if (peerState.queue.length > 0) {
        setImmediate(drainSlice);
      } else {
        peerState.draining = false;
      }
    };

    setImmediate(drainSlice);
  }

  private sendPublishFrame(peerState: PeerState, topic: string, payloadBuffer: Buffer): void {
    const ws = peerState.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return;
    }

    const pubBuf = mqttPacket.generate({
      cmd: 'publish',
      topic,
      payload: payloadBuffer,
      qos: 0,
      retain: false,
      dup: false,
    });

    ws.send(pubBuf, (err) => {
      if (err) {
        if (!this.shuttingDown) {
          console.error(`[PEER:${peerState.target.id}] Failed to forward packet -> ${topic}: ${err.message}`);
        }
      } else {
        peerState.totalForwarded++;
        if (this.debugLog) {
          console.log(`[PEER:${peerState.target.id}] -> Forwarded ${topic} (${payloadBuffer.length} bytes)`);
        }
      }
    });
  }

  public forwardLocalPacket(packet: { topic: string; payload: Buffer | string; qos?: number; retain?: boolean; fromPeer?: boolean }): void {
    if (this.shuttingDown || this.peers.size === 0) {
      return;
    }

    // Defense-in-depth: NEVER forward a packet that arrived from another peer
    if ((packet as any).fromPeer === true) {
      return;
    }

    if (!isForwardableTopic(packet.topic)) {
      return;
    }

    const payloadBuffer = Buffer.isBuffer(packet.payload)
      ? packet.payload
      : Buffer.from(packet.payload);
    const itemBytes = payloadBuffer.length + Buffer.byteLength(packet.topic) + 64;
    const isStatusTopic = packet.topic.endsWith('/status');
    const now = Date.now();

    for (const [id, peerState] of this.peers.entries()) {
      const logPrefix = `[PEER:${id}]`;

      if (
        peerState.connected &&
        !peerState.draining &&
        peerState.queue.length === 0 &&
        peerState.ws &&
        peerState.ws.readyState === WebSocket.OPEN &&
        peerState.ws.bufferedAmount <= MAX_WS_BUFFERED_BYTES
      ) {
        // Connected, no backlog, and socket buffer healthy: send immediately
        this.sendPublishFrame(peerState, packet.topic, payloadBuffer);
      } else {
        // Disconnected or draining backlog: buffer in bounded queue
        this.pruneExpiredQueue(peerState, now);

        // Coalesce /status updates per observer topic in-place so latest status is always kept
        if (isStatusTopic) {
          const existingIdx = peerState.queue.findIndex(q => q.topic === packet.topic);
          if (existingIdx !== -1) {
            const prev = peerState.queue[existingIdx];
            peerState.queuedBytes = Math.max(0, peerState.queuedBytes - prev.byteSize) + itemBytes;
            peerState.queue[existingIdx] = {
              topic: packet.topic,
              payload: payloadBuffer,
              qos: 0,
              retain: false,
              enqueuedAt: now,
              byteSize: itemBytes,
            };
            continue;
          }
        }

        // Enforce both packet-count cap and byte cap
        while (
          peerState.queue.length >= this.maxQueueSize ||
          (peerState.queuedBytes + itemBytes > this.maxQueueBytes && peerState.queue.length > 0)
        ) {
          const dropped = peerState.queue.shift()!;
          peerState.queuedBytes = Math.max(0, peerState.queuedBytes - dropped.byteSize);
          peerState.totalDropped++;
          if (this.debugLog) {
            console.warn(`${logPrefix} Queue capacity reached. Dropped oldest packet.`);
          }
        }

        peerState.queue.push({
          topic: packet.topic,
          payload: payloadBuffer,
          qos: 0,
          retain: false,
          enqueuedAt: now,
          byteSize: itemBytes,
        });
        peerState.queuedBytes += itemBytes;

        if (this.debugLog) {
          console.log(`${logPrefix} Queued packet -> ${packet.topic} (queue: ${peerState.queue.length}/${this.maxQueueSize})`);
        }
      }
    }
  }

  public getPeerStats(): Record<
    string,
    { connected: boolean; queued: number; queuedBytes: number; forwarded: number; dropped: number; url: string }
  > {
    const stats: Record<
      string,
      { connected: boolean; queued: number; queuedBytes: number; forwarded: number; dropped: number; url: string }
    > = {};
    for (const [id, state] of this.peers.entries()) {
      stats[id] = {
        connected: state.connected,
        queued: state.queue.length,
        queuedBytes: state.queuedBytes,
        forwarded: state.totalForwarded,
        dropped: state.totalDropped,
        url: state.target.url,
      };
    }
    return stats;
  }

  public shutdown(): void {
    this.shuttingDown = true;
    for (const [id, state] of this.peers.entries()) {
      this.clearPeerTimers(state);
      if (state.reconnectTimer) {
        clearTimeout(state.reconnectTimer);
        state.reconnectTimer = undefined;
      }
      console.log(`[PEER:${id}] Disconnecting peer bridge client...`);
      try {
        if (state.ws) {
          if (state.ws.readyState === WebSocket.OPEN) {
            const discBuf = mqttPacket.generate({ cmd: 'disconnect' });
            state.ws.send(discBuf, () => {});
          }
          state.ws.terminate();
          state.ws = null;
        }
      } catch {
        // Ignore errors during termination
      }
    }
    this.peers.clear();
  }
}
