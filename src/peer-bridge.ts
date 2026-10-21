import mqtt, { MqttClient } from 'mqtt';
import { PeerConfig, PeerTarget } from './config';

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

// Validate inbound packet published by a peer broker (Role 4)
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
  private shuttingDown: boolean = false;

  constructor(config: PeerConfig) {
    this.maxQueueSize = config.maxQueueSize;

    if (config.peers.length === 0) {
      console.log('[PEER_BRIDGE] No outbound peer brokers configured');
      return;
    }

    console.log(`[PEER_BRIDGE] Initializing ${config.peers.length} outbound peer bridge(s) (queue limit: ${this.maxQueueSize})`);

    for (const target of config.peers) {
      this.initPeer(target);
    }
  }

  private initPeer(target: PeerTarget): void {
    const logPrefix = `[PEER:${target.id}]`;
    console.log(`${logPrefix} Connecting to ${target.url} as "${target.username}"...`);

    const client = mqtt.connect(target.url, {
      username: target.username,
      password: target.password,
      reconnectPeriod: 5000,
      connectTimeout: 10000,
      clean: true,
      clientId: `meshcore_peer_${target.id}_${Math.random().toString(16).substring(2, 8)}`,
    });

    const peerState: PeerState = {
      target,
      client,
      connected: false,
      queue: [],
      totalForwarded: 0,
      totalDropped: 0,
    };

    this.peers.set(target.id, peerState);

    client.on('connect', () => {
      peerState.connected = true;
      console.log(`${logPrefix} ✓ Connected to peer at ${target.url}`);
      this.drainQueue(peerState);
    });

    client.on('reconnect', () => {
      console.log(`${logPrefix} Reconnecting to ${target.url}...`);
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
      console.log(`[PEER:${id}] Disconnecting peer bridge client...`);
      try {
        state.client.end(true);
      } catch (err) {
        // Ignore errors during termination
      }
    }
    this.peers.clear();
  }
}
