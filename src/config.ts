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
  username: string;
  password: string;
}

export interface PeerConfig {
  peers: PeerTarget[];
  maxQueueSize: number;
}

// Parse a single PEER_N config string in format: URL:username:password
// e.g. ws://guy-a.example.com:8883:peer_user:peer_secret
export function parsePeerString(peerStr: string, id: string): PeerTarget | null {
  const trimmed = peerStr.trim();
  const lastColon = trimmed.lastIndexOf(':');
  if (lastColon === -1) return null;
  const secondLastColon = trimmed.lastIndexOf(':', lastColon - 1);
  if (secondLastColon === -1) return null;

  let url = trimmed.substring(0, secondLastColon).trim();
  const username = trimmed.substring(secondLastColon + 1, lastColon).trim();
  const password = trimmed.substring(lastColon + 1).trim();

  if (!url || !username || !password) return null;

  if (!url.includes('://')) {
    url = `ws://${url}`;
  }

  return { id, url, username, password };
}

// Load outbound peer configuration (PEER_1, PEER_2, ...)
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
      console.log(`[CONFIG] Loaded outbound peer: ${peer.id} -> ${peer.url} (user: ${peer.username})`);
    } else {
      console.warn(`[CONFIG] Invalid format for PEER_${peerIndex}: "${peerEnvVar}". Expected URL:username:password`);
    }

    peerIndex++;
  }

  const maxQueueSize = parseInt(process.env.PEER_QUEUE_MAX_SIZE || '1000', 10);

  return {
    peers,
    maxQueueSize: isNaN(maxQueueSize) || maxQueueSize <= 0 ? 1000 : maxQueueSize,
  };
}
