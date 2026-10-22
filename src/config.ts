import { config as dotenvConfig } from 'dotenv';
import { AbuseConfig } from './abuse-detector';

// Load environment variables
dotenvConfig();

// Validate required environment variables
function validateRequiredEnvVars(vars: string[]): void {
  for (const envVar of vars) {
    if (process.env[envVar] === undefined) {
      console.error(`FATAL: Missing required environment variable: ${envVar}`);
      console.error(`Please check your .env file and ensure all variables from .env.example are set.`);
      process.exit(1);
    }
  }
}

// Validate and load MQTT configuration
export function loadMqttConfig() {
  validateRequiredEnvVars([
    'MQTT_WS_PORT',
    'MQTT_HOST',
    'AUTH_EXPECTED_AUDIENCE',
  ]);

  return {
    wsPort: parseInt(process.env.MQTT_WS_PORT!),
    host: process.env.MQTT_HOST!,
    expectedAudience: process.env.AUTH_EXPECTED_AUDIENCE!,
  };
}

// Validate and load subscriber configuration
export function loadSubscriberConfig() {
  validateRequiredEnvVars([
    'SUBSCRIBER_MAX_CONNECTIONS_DEFAULT',
  ]);

  return {
    defaultMaxConnections: parseInt(process.env.SUBSCRIBER_MAX_CONNECTIONS_DEFAULT!),
  };
}

// Validate and load abuse detection configuration
export function loadAbuseConfig(): AbuseConfig {
  validateRequiredEnvVars([
    'ABUSE_DUPLICATE_WINDOW_SIZE',
    'ABUSE_DUPLICATE_WINDOW_MS',
    'ABUSE_DUPLICATE_THRESHOLD',
    'ABUSE_BUCKET_CAPACITY',
    'ABUSE_BUCKET_REFILL_RATE',
    'ABUSE_MAX_PACKET_SIZE',
    'ABUSE_MAX_TOPICS_PER_DAY',
    'ABUSE_ANOMALY_THRESHOLD',
    'ABUSE_MAX_IATA_CHANGES_24H',
    'ABUSE_TOPIC_HISTORY_SIZE',
    'ABUSE_TOPIC_HISTORY_WINDOW_MS',
    'ABUSE_PERSISTENCE_PATH',
    'ABUSE_PERSISTENCE_INTERVAL_MS',
    'ABUSE_ENFORCEMENT_ENABLED',
  ]);

  return {
    duplicateWindowSize: parseInt(process.env.ABUSE_DUPLICATE_WINDOW_SIZE!),
    duplicateWindowMs: parseInt(process.env.ABUSE_DUPLICATE_WINDOW_MS!),
    duplicateThreshold: parseInt(process.env.ABUSE_DUPLICATE_THRESHOLD!),
    maxDuplicatesPerPacket: parseInt(process.env.ABUSE_MAX_DUPLICATES_PER_PACKET || '5'),
    duplicateRateThreshold: parseFloat(process.env.ABUSE_DUPLICATE_RATE_THRESHOLD || '0.3'),
    duplicateRateWindowMs: parseInt(process.env.ABUSE_DUPLICATE_RATE_WINDOW_MS || '300000'),
    bucketCapacity: parseInt(process.env.ABUSE_BUCKET_CAPACITY!),
    bucketRefillRate: parseFloat(process.env.ABUSE_BUCKET_REFILL_RATE!),
    maxPacketSize: parseInt(process.env.ABUSE_MAX_PACKET_SIZE!),
    maxTopicsPerDay: parseInt(process.env.ABUSE_MAX_TOPICS_PER_DAY!),
    anomalyThreshold: parseInt(process.env.ABUSE_ANOMALY_THRESHOLD!),
    maxIataChanges24h: parseInt(process.env.ABUSE_MAX_IATA_CHANGES_24H!),
    topicHistorySize: parseInt(process.env.ABUSE_TOPIC_HISTORY_SIZE!),
    topicHistoryWindowMs: parseInt(process.env.ABUSE_TOPIC_HISTORY_WINDOW_MS!),
    persistencePath: process.env.ABUSE_PERSISTENCE_PATH!,
    persistenceIntervalMs: parseInt(process.env.ABUSE_PERSISTENCE_INTERVAL_MS!),
    // Optional; defaults to 7 days. Clients with no activity within this window are evicted.
    stateRetentionMs: parseInt(process.env.ABUSE_STATE_RETENTION_MS || '604800000'),
    enforcementEnabled: process.env.ABUSE_ENFORCEMENT_ENABLED === 'true',
  };
}

export interface PeerTarget {
  id: string;
  url: string;
  targetAudience: string;
  username?: string;
  password?: string;
}

export interface PeerConfig {
  peerPrivateKey?: string;
  authorizedPeerKeys: Set<string>;
  peers: PeerTarget[];
  maxQueueSize: number;
}

// Parse a single PEER_N config string:
// 1. JWT Interconnect: URL:targetAudience (e.g. ws://guy-a.example.com:8883:guy_a_audience)
// 2. Legacy Credentials: URL:username:password (e.g. ws://guy-a.example.com:8883:peer_user:peer_pass)
export function parsePeerString(peerStr: string, id: string): PeerTarget | null {
  const trimmed = peerStr.trim();
  if (!trimmed) return null;

  let scheme = '';
  let rest = trimmed;
  const schemeMatch = trimmed.match(/^([a-zA-Z]+:\/\/)(.*)$/);
  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase();
    rest = schemeMatch[2];
    if (scheme !== 'ws://' && scheme !== 'wss://') {
      return null;
    }
  }

  const parts = rest.split(':').map(p => p.trim());
  if (parts.some(p => p.length === 0)) {
    return null; // Reject strings like '::' or empty segments
  }

  if (scheme) {
    // Has explicit ws:// or wss://
    if (parts.length === 1) {
      return null; // Missing audience or credentials
    } else if (parts.length === 2) {
      // ws://host/path:audience
      return { id, url: `${scheme}${parts[0]}`, targetAudience: parts[1] };
    } else if (parts.length === 3) {
      // Could be:
      // ws://host:port:audience
      // or ws://host/path:username:password
      const isPort = /^\d+$/.test(parts[1]) || /^\d+\//.test(parts[1]);
      if (isPort) {
        return { id, url: `${scheme}${parts[0]}:${parts[1]}`, targetAudience: parts[2] };
      } else {
        return { id, url: `${scheme}${parts[0]}`, targetAudience: parts[1], username: parts[1], password: parts[2] };
      }
    } else if (parts.length >= 4) {
      // ws://host:port:username:password
      const url = `${scheme}${parts[0]}:${parts[1]}`;
      const username = parts[2];
      const password = parts.slice(3).join(':');
      return { id, url, targetAudience: username, username, password };
    }
  } else {
    // No explicit scheme: prepends ws://
    if (parts.length <= 2) {
      return null; // e.g. 'one:colon' or 'nocolons'
    } else if (parts.length === 3) {
      // host:port:audience
      const isPort = /^\d+$/.test(parts[1]) || /^\d+\//.test(parts[1]);
      if (isPort) {
        return { id, url: `ws://${parts[0]}:${parts[1]}`, targetAudience: parts[2] };
      } else {
        return { id, url: `ws://${parts[0]}`, targetAudience: parts[1], username: parts[1], password: parts[2] };
      }
    } else if (parts.length >= 4) {
      // host:port:username:password
      const url = `ws://${parts[0]}:${parts[1]}`;
      const username = parts[2];
      const password = parts.slice(3).join(':');
      return { id, url, targetAudience: username, username, password };
    }
  }

  return null;
}

// Load authorized remote peer public keys (comma-separated or indexed)
export function loadAuthorizedPeerKeys(): Set<string> {
  const authorized = new Set<string>();

  // 1. AUTHORIZED_PEERS=PUBKEY1,PUBKEY2
  if (process.env.AUTHORIZED_PEERS) {
    const keys = process.env.AUTHORIZED_PEERS.split(',')
      .map(k => k.trim().toUpperCase())
      .filter(k => /^[0-9A-F]{64}$/i.test(k));
    for (const key of keys) {
      authorized.add(key);
    }
  }

  // 2. PEER_1_KEY, PEER_2_KEY...
  let i = 1;
  while (true) {
    const key = process.env[`PEER_${i}_KEY`];
    if (!key) break;
    const clean = key.trim().toUpperCase();
    if (/^[0-9A-F]{64}$/i.test(clean)) {
      authorized.add(clean);
    }
    i++;
  }

  return authorized;
}

// Load peer configuration
export function loadPeerConfig(): PeerConfig {
  const peers: PeerTarget[] = [];
  let peerIndex = 1;

  while (true) {
    const peerEnvVar = process.env[`PEER_${peerIndex}`];
    if (!peerEnvVar) {
      break;
    }

    const peer = parsePeerString(peerEnvVar, `peer_${peerIndex}`);
    if (peer) {
      peers.push(peer);
      console.log(`[CONFIG] Loaded outbound peer: ${peer.id} -> ${peer.url} (audience: ${peer.targetAudience})`);
    } else {
      console.warn(`[CONFIG] Invalid format for PEER_${peerIndex}: "${peerEnvVar}". Expected URL:targetAudience or URL:username:password`);
    }

    peerIndex++;
  }

  const authorizedPeerKeys = loadAuthorizedPeerKeys();
  if (authorizedPeerKeys.size > 0) {
    console.log(`[CONFIG] Loaded ${authorizedPeerKeys.size} authorized peer public key(s)`);
  }

  const maxQueueSize = parseInt(process.env.PEER_QUEUE_MAX_SIZE || '1000', 10);

  return {
    peerPrivateKey: process.env.PEER_PRIVATE_KEY?.trim() || undefined,
    authorizedPeerKeys,
    peers,
    maxQueueSize: isNaN(maxQueueSize) || maxQueueSize <= 0 ? 1000 : maxQueueSize,
  };
}
