import { connect, MqttClient, IClientOptions } from 'mqtt';
import WebSocket from 'ws';
import { UpstreamPeerConfig } from './config';

// Headers exchanged between peered brokers on the WebSocket upgrade request
export const PEER_SECRET_HEADER = 'x-meshcore-peer-secret';
export const PEER_VIA_HEADER = 'x-meshcore-via';
// Bound on forwarding hops; also caps the size of the via header
export const MAX_PEER_HOPS = 8;

// Messages buffered per link while the upstream connection is not (yet) established
const MAX_PENDING_MESSAGES = 100;
const RECONNECT_PERIOD_MS = 5000;
const CONNECT_TIMEOUT_MS = 15000;
// After an upstream rejects us at the WebSocket upgrade (unknown peer / bad secret),
// stop opening new links to it for a while so we don't trip its rate limiter
const PEER_REJECTED_BACKOFF_MS = 5 * 60 * 1000;

export interface ForwardSession {
  username: string;
  password: string;
  clientId: string;
  publicKey: string;
  will?: { topic: string; payload: Buffer; qos: 0 | 1 | 2; retain: boolean } | null;
  // Broker identities this session has already traversed (for loop prevention)
  via: string[];
}

interface ForwardMessage {
  topic: string;
  payload: Buffer;
  qos: 0 | 1 | 2;
  retain: boolean;
}

class UpstreamLink {
  private client: MqttClient;
  private pending: ForwardMessage[] = [];
  private closed = false;
  private readonly logPrefix: string;

  constructor(private peer: UpstreamPeerConfig, session: ForwardSession, private onRejected: () => void) {
    this.logPrefix = `[O:${session.publicKey.substring(0, 8)}] [PEER:${peer.host}]`;

    const headers: Record<string, string> = {
      [PEER_VIA_HEADER]: session.via.join(','),
    };
    if (peer.secret) {
      headers[PEER_SECRET_HEADER] = peer.secret;
    }

    const options: IClientOptions = {
      clientId: `peer_${peer.name}_${session.clientId}`,
      username: session.username,
      password: session.password,
      protocolVersion: 4,
      clean: true,
      keepalive: 60,
      reconnectPeriod: RECONNECT_PERIOD_MS,
      connectTimeout: CONNECT_TIMEOUT_MS,
      queueQoSZero: false,
      wsOptions: { headers },
      // Create the socket ourselves: mqtt.js swallows WebSocket upgrade failures,
      // but we need the HTTP status to tell a peer rejection apart from an outage
      createWebsocket: (url, protocols, opts) => {
        const socket = new WebSocket(url, protocols, opts.wsOptions as WebSocket.ClientOptions);
        socket.on('error', (err) => this.handleSocketError(err));
        return socket;
      },
    };
    // Mirror the publisher's will so the upstream reports it offline if this broker drops
    if (session.will) {
      options.will = {
        topic: session.will.topic,
        payload: session.will.payload,
        qos: session.will.qos,
        retain: session.will.retain,
      };
    }

    this.client = connect(peer.url, options);

    this.client.on('connect', () => {
      console.log(`${this.logPrefix} Forwarding link established`);
      const queued = this.pending;
      this.pending = [];
      for (const message of queued) {
        this.publish(message);
      }
    });

    this.client.on('error', (err: Error & { code?: number | string }) => {
      if (this.closed) return;

      // CONNACK refusal: the upstream rejected the publisher's credentials (e.g. audience
      // mismatch or expired token). Retrying with the same token cannot succeed.
      if (typeof err.code === 'number' && err.code !== 0) {
        console.log(`${this.logPrefix} ✗ Upstream refused connection: ${err.message} - giving up on this link`);
        this.close(true);
      }
      // Transport errors are logged by handleSocketError
    });

    this.client.on('offline', () => {
      if (!this.closed) {
        console.log(`${this.logPrefix} Link offline, will retry in ${RECONNECT_PERIOD_MS / 1000}s`);
      }
    });
  }

  private handleSocketError(err: Error): void {
    if (this.closed) return;

    // WebSocket upgrade rejected by the upstream broker
    const status = err.message.match(/Unexpected server response: (\d+)/);
    if (!status) {
      console.log(`${this.logPrefix} Link error: ${err.message}`);
      return;
    }
    const code = parseInt(status[1]);
    if (code === 508) {
      console.log(`${this.logPrefix} Upstream reported a forwarding loop - not forwarding this session`);
      this.close(true);
    } else if (code === 401 || code === 403 || code === 429) {
      console.log(`${this.logPrefix} ✗ Upstream rejected peer "${this.peer.name}" (HTTP ${code}) - check its DOWNSTREAM_PEER config and secret; pausing new links for ${PEER_REJECTED_BACKOFF_MS / 60000} min`);
      this.onRejected();
      this.close(true);
    } else {
      console.log(`${this.logPrefix} Upstream returned HTTP ${code}, will retry`);
    }
  }

  forward(message: ForwardMessage): void {
    if (this.closed) return;
    if (this.client.connected) {
      this.publish(message);
      return;
    }
    if (this.pending.length >= MAX_PENDING_MESSAGES) {
      this.pending.shift();
    }
    this.pending.push(message);
  }

  // Graceful close sends DISCONNECT (upstream discards the will);
  // force skips waiting for in-flight messages.
  close(force = false): void {
    if (this.closed) return;
    this.closed = true;
    this.pending = [];
    this.client.end(force);
  }

  private publish(message: ForwardMessage): void {
    this.client.publish(message.topic, message.payload, { qos: message.qos, retain: message.retain }, (err) => {
      if (err && !this.closed) {
        console.log(`${this.logPrefix} Failed to forward ${message.topic}: ${err.message}`);
      }
    });
  }
}

/**
 * Mirrors authenticated publisher sessions to upstream brokers.
 *
 * Each publisher gets one MQTT connection per upstream peer, authenticated with the
 * publisher's own username and signed token. The upstream validates that token against
 * this broker's audience because the connection is made on its "/_<peer-name>" path.
 */
export class PeerForwarder {
  private sessions = new Map<object, UpstreamLink[]>();
  private rejectedUntil = new Map<string, number>();

  constructor(private peers: UpstreamPeerConfig[]) {}

  get enabled(): boolean {
    return this.peers.length > 0;
  }

  open(key: object, session: ForwardSession): void {
    if (!this.enabled || this.sessions.has(key)) return;

    const now = Date.now();
    const links: UpstreamLink[] = [];
    for (const peer of this.peers) {
      if ((this.rejectedUntil.get(peer.url) || 0) > now) continue;
      links.push(new UpstreamLink(peer, session, () => {
        this.rejectedUntil.set(peer.url, Date.now() + PEER_REJECTED_BACKOFF_MS);
      }));
    }
    this.sessions.set(key, links);
  }

  forward(key: object, packet: { topic: string; payload: Buffer | string; qos: number; retain: boolean }): void {
    const links = this.sessions.get(key);
    if (!links) return;
    const message: ForwardMessage = {
      topic: packet.topic,
      // Copy so later mutation of the packet (e.g. subscriber filtering) can't affect it
      payload: Buffer.from(packet.payload),
      qos: packet.qos as 0 | 1 | 2,
      retain: packet.retain,
    };
    for (const link of links) {
      link.forward(message);
    }
  }

  close(key: object): void {
    const links = this.sessions.get(key);
    if (!links) return;
    this.sessions.delete(key);
    for (const link of links) {
      link.close();
    }
  }

  shutdown(): void {
    for (const key of Array.from(this.sessions.keys())) {
      this.close(key);
    }
  }
}
