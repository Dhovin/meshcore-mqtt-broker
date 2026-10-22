import mqtt, { MqttClient } from 'mqtt';
import { PeerConfig, PeerTarget } from './config';
import { PeerKeyPair, createPeerJwt } from './peer-crypto';

export interface QueueItem {
  topic: string;
  payload: Buffer;
  qos: 0 | 1;
  retain: boolean;
  enqueuedAt: number;
}

export interface PeerState {
  target: PeerTarget;
  client: MqttClient;
  connected: boolean;
  queue: QueueItem[];
  totalForwarded: number;
  totalDropped: number;
  tokenRefreshTimer?: NodeJS.Timeout;
}

// Subtopics allowed for broker-to-broker forwarding
export const ALLOWED_PEER_SUBTOPICS = ['packets', 'status', 'neighbors', 'raw'];

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
}

// Validate inbound packet published by a peer broker (JWT Peer or Role 4)
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

    const normalizedLocation = isTestRegion ? 'test' : locationCode.toUpperCase();
    const normalizedTopic = `meshcore/${normalizedLocation}/${topicPublicKey}/${subtopic}`;
    const originId = message.origin_id.toString().trim().toUpperCase();

    return {
      valid: true,
      normalizedTopic,
      originId,
      normalizedLocation,
    };
  } catch (err) {
    return { valid: false, error: 'Invalid JSON payload in peer packet' };
  }
}

export class PeerBridgeManager {
  private peers: Map<string, PeerState> = new Map();
  private maxQueueSize: number;
  private identity?: PeerKeyPair;
  private shuttingDown: boolean = false;

  constructor(config: PeerConfig, identity?: PeerKeyPair) {
    this.maxQueueSize = config.maxQueueSize;
    this.identity = identity;

    if (config.peers.length === 0) {
      console.log('[PEER_BRIDGE] No outbound peer brokers configured');
      return;
    }

    console.log(`[PEER_BRIDGE] Initializing ${config.peers.length} outbound peer bridge(s) (queue limit: ${this.maxQueueSize})`);

    for (const target of config.peers) {
      this.initPeer(target);
    }
  }

  private async initPeer(target: PeerTarget): Promise<void> {
    const logPrefix = `[PEER:${target.id}]`;

    const peerState: PeerState = {
      target,
      client: null as any,
      connected: false,
      queue: [],
      totalForwarded: 0,
      totalDropped: 0,
    };
    this.peers.set(target.id, peerState);

    let username: string;
    let password: string;

    if (target.username && target.password) {
      // Legacy credentials
      username = target.username;
      password = target.password;
      console.log(`${logPrefix} Connecting to ${target.url} using credentials for "${username}"...`);
    } else if (this.identity) {
      // Native MeshCore JWT authentication
      username = `v1_${this.identity.publicKeyHex}`;
      password = await createPeerJwt(this.identity, target.targetAudience, 86400);
      console.log(`${logPrefix} Connecting to ${target.url} via JWT [pubkey: ${this.identity.publicKeyHex.substring(0, 8)}..., aud: ${target.targetAudience}]...`);
    } else {
      console.error(`${logPrefix} Cannot connect to peer: neither credentials nor peer identity provided`);
      return;
    }

    if (this.shuttingDown) return;

    const clientId = `meshcore_peer_${target.id}_${Math.random().toString(16).substring(2, 8)}`;

    const client = mqtt.connect(target.url, {
      username,
      password,
      reconnectPeriod: 5000,
      connectTimeout: 10000,
      clean: true,
      clientId,
    });

    peerState.client = client;

    // If using JWT, periodically refresh token (every 12 hours) so reconnects always have fresh JWT
    if (this.identity && !target.username) {
      peerState.tokenRefreshTimer = setInterval(async () => {
        try {
          if (this.identity && peerState.client) {
            const freshToken = await createPeerJwt(this.identity, target.targetAudience, 86400);
            (peerState.client as any).options.password = freshToken;
            console.log(`${logPrefix} Refreshed JWT token for target audience "${target.targetAudience}"`);
          }
        } catch (err: any) {
          console.warn(`${logPrefix} Failed to refresh JWT token: ${err.message}`);
        }
      }, 12 * 60 * 60 * 1000);
    }

    client.on('connect', () => {
      peerState.connected = true;
      console.log(`${logPrefix} ✓ Connected to peer at ${target.url}`);
      this.drainQueue(peerState);
    });

    client.on('reconnect', async () => {
      console.log(`${logPrefix} Reconnecting to ${target.url}...`);
      // Update with fresh token on reconnect if using JWT
      if (this.identity && !target.username) {
        try {
          const freshToken = await createPeerJwt(this.identity, target.targetAudience, 86400);
          (client as any).options.password = freshToken;
        } catch (err: any) {
          console.warn(`${logPrefix} Error updating token on reconnect: ${err.message}`);
        }
      }
    });

    client.on('close', () => {
      if (peerState.connected) {
        console.log(`${logPrefix} ✗ Connection closed (buffered packets: ${peerState.queue.length})`);
      }
      peerState.connected = false;
    });

    client.on('error', (err) => {
      console.error(`${logPrefix} [ERROR] ${err.message}`);
    });
  }

  private drainQueue(peerState: PeerState): void {
    const logPrefix = `[PEER:${peerState.target.id}]`;
    if (peerState.queue.length === 0) return;

    console.log(`${logPrefix} Draining ${peerState.queue.length} queued packet(s)...`);

    while (peerState.queue.length > 0 && peerState.connected) {
      const item = peerState.queue.shift();
      if (!item) break;

      peerState.client.publish(item.topic, item.payload, { qos: item.qos, retain: item.retain }, (err) => {
        if (err) {
          console.error(`${logPrefix} Error publishing queued packet -> ${item.topic}:`, err.message);
        } else {
          peerState.totalForwarded++;
        }
      });
    }
  }

  public forwardLocalPacket(packet: { topic: string; payload: Buffer | string; qos?: number; retain?: boolean }): void {
    if (this.shuttingDown || this.peers.size === 0) {
      return;
    }

    if (!isForwardableTopic(packet.topic)) {
      return;
    }

    const payloadBuffer = Buffer.isBuffer(packet.payload)
      ? packet.payload
      : Buffer.from(packet.payload);

    for (const [id, peerState] of this.peers.entries()) {
      const logPrefix = `[PEER:${id}]`;

      if (peerState.connected && peerState.queue.length === 0) {
        // Connected and no backlog: publish directly
        peerState.client.publish(
          packet.topic,
          payloadBuffer,
          { qos: 0, retain: false },
          (err) => {
            if (err) {
              console.error(`${logPrefix} Failed to forward packet -> ${packet.topic}:`, err.message);
            } else {
              peerState.totalForwarded++;
              console.log(`${logPrefix} -> Forwarded ${packet.topic} (${payloadBuffer.length} bytes)`);
            }
          }
        );
      } else {
        // Disconnected or draining queue: buffer packet
        if (peerState.queue.length >= this.maxQueueSize) {
          peerState.queue.shift(); // Drop oldest packet
          peerState.totalDropped++;
          console.warn(`${logPrefix} Queue capacity reached (${this.maxQueueSize}). Dropped oldest packet.`);
        }

        peerState.queue.push({
          topic: packet.topic,
          payload: payloadBuffer,
          qos: 0,
          retain: false,
          enqueuedAt: Date.now(),
        });

        console.log(`${logPrefix} Queued packet -> ${packet.topic} (queue: ${peerState.queue.length}/${this.maxQueueSize})`);
      }
    }
  }

  public getPeerStats(): Record<string, { connected: boolean; queued: number; forwarded: number; dropped: number; url: string }> {
    const stats: Record<string, any> = {};
    for (const [id, state] of this.peers.entries()) {
      stats[id] = {
        connected: state.connected,
        queued: state.queue.length,
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
      if (state.tokenRefreshTimer) {
        clearInterval(state.tokenRefreshTimer);
      }
      console.log(`[PEER:${id}] Disconnecting peer bridge client...`);
      try {
        if (state.client) {
          state.client.end(true);
        }
      } catch (err) {
        // Ignore errors during termination
      }
    }
    this.peers.clear();
  }
}
