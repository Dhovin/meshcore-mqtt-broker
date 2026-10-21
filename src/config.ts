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

// Broker peering
//
// Upstream peers: brokers this broker forwards its publishers' traffic to.
//   UPSTREAM_PEER_N=wss://mqtt.upstream.com:443/_mybroker
//   UPSTREAM_PEER_N_SECRET=optional-shared-secret
// The path segment after "/_" is the name this broker is registered under on the upstream.
//
// Downstream peers: brokers allowed to forward their publishers' traffic to this broker.
//   DOWNSTREAM_PEER_N=mybroker:mqtt.mybroker.com[,another.audience.com]
//   DOWNSTREAM_PEER_N_SECRET=optional-shared-secret
// Connections on path "/_mybroker" validate publisher tokens against the listed audience(s)
// instead of AUTH_EXPECTED_AUDIENCE. Connections on "/_<name>" for an undefined peer are denied.

export interface UpstreamPeerConfig {
  url: string;
  host: string;
  name: string;
  secret?: string;
}

export interface DownstreamPeerConfig {
  name: string;
  audiences: string[];
  secret?: string;
}

export const PEER_NAME_REGEX = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const PEER_PATH_REGEX = /^\/_([^/]*)\/?$/;

function fatalConfig(message: string): never {
  console.error(`FATAL: ${message}`);
  process.exit(1);
}

export function loadPeerConfig() {
  const upstream: UpstreamPeerConfig[] = [];
  for (let i = 1; process.env[`UPSTREAM_PEER_${i}`]; i++) {
    const raw = process.env[`UPSTREAM_PEER_${i}`]!.trim();
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      fatalConfig(`UPSTREAM_PEER_${i} is not a valid URL: ${raw}`);
    }
    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
      fatalConfig(`UPSTREAM_PEER_${i} must use ws:// or wss:// (got ${parsed.protocol})`);
    }
    if (parsed.username || parsed.password) {
      fatalConfig(`UPSTREAM_PEER_${i} must not contain credentials; use UPSTREAM_PEER_${i}_SECRET instead`);
    }
    const match = parsed.pathname.match(PEER_PATH_REGEX);
    if (!match || !PEER_NAME_REGEX.test(match[1])) {
      fatalConfig(`UPSTREAM_PEER_${i} path must be /_<peer-name> (e.g. wss://mqtt.upstream.com:443/_mybroker), got: ${parsed.pathname}`);
    }
    upstream.push({
      url: parsed.toString(),
      host: parsed.host,
      name: match[1],
      secret: process.env[`UPSTREAM_PEER_${i}_SECRET`] || undefined,
    });
  }

  const downstream = new Map<string, DownstreamPeerConfig>();
  for (let i = 1; process.env[`DOWNSTREAM_PEER_${i}`]; i++) {
    const raw = process.env[`DOWNSTREAM_PEER_${i}`]!.trim();
    const sep = raw.indexOf(':');
    const name = sep === -1 ? raw : raw.substring(0, sep).trim();
    const audiences = sep === -1 ? [] : raw.substring(sep + 1).split(',').map(a => a.trim()).filter(Boolean);
    if (!PEER_NAME_REGEX.test(name)) {
      fatalConfig(`DOWNSTREAM_PEER_${i} has an invalid peer name "${name}" (allowed: letters, digits, . _ -)`);
    }
    if (audiences.length === 0) {
      fatalConfig(`DOWNSTREAM_PEER_${i} must be in the format name:audience[,audience...]`);
    }
    if (downstream.has(name)) {
      fatalConfig(`DOWNSTREAM_PEER_${i} duplicates peer name "${name}"`);
    }
    downstream.set(name, {
      name,
      audiences,
      secret: process.env[`DOWNSTREAM_PEER_${i}_SECRET`] || undefined,
    });
  }

  return { upstream, downstream };
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

