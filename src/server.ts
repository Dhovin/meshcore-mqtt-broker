import Aedes from 'aedes';
import { createServer } from 'http';
import { createServer as createTcpServer } from 'net';
import { WebSocketServer } from 'ws';
import { Duplex } from 'stream';
import { readFileSync } from 'fs';
import { dirname } from 'path';
import { createHash } from 'crypto';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { getAirportInfo } from 'airport-utils';
import { RateLimiter } from './rate-limiter.js';
import { getClientIP } from './ip-utils.js';
import { AbuseDetector } from './abuse-detector.js';
import { loadMqttConfig, loadAbuseConfig, loadSubscriberConfig, loadPeerConfig } from './config.js';
import { timingSafeCompare } from './crypto-utils.js';
import { MqttStreamValidator } from './mqtt-packet-validator.js';
import { SysMetricsCollector, SubscriberAccountMeta } from './sys-metrics.js';
import { PeerBridgeManager, validatePeerPacket } from './peer-bridge.js';
import { loadOrCreatePeerIdentity, PeerKeyPair } from './peer-crypto.js';

// Read broker version from package.json
let brokerVersion = '1.0.4';
try {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'));
  if (pkg.version) brokerVersion = pkg.version;
} catch {
  // Fallback to 1.0.4 if package.json cannot be read
}

// Load and validate configuration
const mqttConfig = loadMqttConfig();
const abuseConfig = loadAbuseConfig();
const subscriberConfig = loadSubscriberConfig();
const peerConfig = loadPeerConfig();
const isDebug = mqttConfig.logLevel === 'debug';

const WS_PORT = mqttConfig.wsPort;
const TCP_PORT = mqttConfig.tcpPort;
const ENABLE_TCP = mqttConfig.enableTcp;
const HOST = mqttConfig.host;
const EXPECTED_AUDIENCE = mqttConfig.expectedAudience;
const HTTP_REDIRECT_URL = mqttConfig.httpRedirectUrl;

// Always initialize the broker's Ed25519 peer identity on startup (persisted in /data/peer-identity.json)
// so its public key is immediately visible in the startup banner and $SYS telemetry.
let peerIdentity: PeerKeyPair | undefined;
let peerBridgeManager: PeerBridgeManager | undefined;

try {
  const dataDir = dirname(abuseConfig.persistencePath);
  peerIdentity = await loadOrCreatePeerIdentity(peerConfig.peerPrivateKey, dataDir);
  console.log(`[PEER] Broker peer identity initialized - Public Key: ${peerIdentity.publicKeyHex}`);
} catch (err: any) {
  console.error(`[PEER] Failed to initialize peer identity: ${err?.message || err}`);
}

if (peerConfig.peers.length > 0) {
  peerBridgeManager = new PeerBridgeManager(peerConfig, peerIdentity, isDebug);
}

// Helper function to validate IATA airport codes
function isValidIATACode(code: string): boolean {
  try {
    getAirportInfo(code);
    return true;
  } catch {
    return false;
  }
}

// Allowed publisher subtopics
const ALLOWED_PUBLISHER_SUBTOPICS = new Set([
  'packets',
  'status',
  'neighbors',
  'raw',
  'serial/responses',
]);

// Client types
enum ClientType {
  SUBSCRIBER = 'subscriber',
  PUBLISHER = 'publisher',
  PEER = 'peer',
}

// Subscriber roles
enum SubscriberRole {
  ADMIN = 1,           // Full access + can delete retained messages
  FULL_ACCESS = 2,     // Full access, no hidden data
  LIMITED = 3,         // All access but with hidden/sensitive data filtered
  PEER = 4,            // Inbound peer broker connection (publish-only)
}

// Load subscriber users from environment variables
// Format: SUBSCRIBER_1=username:password:role:maxConnections, SUBSCRIBER_2=username:password:role:maxConnections, etc.
// Role: 1=admin (full+delete), 2=full_access (no hidden data), 3=limited (filtered data), 4=peer (inbound peer broker)
// maxConnections: number for override, D or omit to use default
const subscriberUsers = new Map<string, string>();
const subscriberRoles = new Map<string, SubscriberRole>();
const subscriberMaxConnections = new Map<string, number>();

// Track active connections per subscriber username
const subscriberActiveConnections = new Map<string, Set<string>>();
const subscriberAccountsMeta = new Map<string, SubscriberAccountMeta>();

let subscriberIndex = 1;
while (true) {
  const subscriberEnvVar = process.env[`SUBSCRIBER_${subscriberIndex}`];
  if (!subscriberEnvVar) {
    break;
  }
  
  const parts = subscriberEnvVar.split(':').map(s => s.trim());
  const username = parts[0];
  const password = parts[1];
  const roleStr = parts[2];
  const maxConnStr = parts[3];
  
  if (username && password) {
    subscriberUsers.set(username, password);
    
    // Parse and store role (default to LIMITED if not specified or invalid)
    let role = SubscriberRole.LIMITED;
    if (roleStr) {
      const roleNum = parseInt(roleStr);
      if (roleNum === 1 || roleNum === 2 || roleNum === 3 || roleNum === 4) {
        role = roleNum as SubscriberRole;
      }
    }
    subscriberRoles.set(username, role);
    
    // Parse and store max connections (D or empty = default, number = override)
    let maxConn = subscriberConfig.defaultMaxConnections;
    if (maxConnStr && maxConnStr.toUpperCase() !== 'D') {
      const parsedMax = parseInt(maxConnStr);
      if (!isNaN(parsedMax) && parsedMax > 0) {
        maxConn = parsedMax;
      }
    }
    subscriberMaxConnections.set(username, maxConn);
    
    // Initialize active connections set for this user
    const activeSet = new Set<string>();
    subscriberActiveConnections.set(username, activeSet);
    
    const roleNames: Record<SubscriberRole, string> = {
      [SubscriberRole.ADMIN]: 'admin',
      [SubscriberRole.FULL_ACCESS]: 'full_access', 
      [SubscriberRole.LIMITED]: 'limited',
      [SubscriberRole.PEER]: 'peer',
    };
    subscriberAccountsMeta.set(username, {
      roleName: roleNames[role],
      maxConnections: maxConn,
      activeConnections: activeSet,
    });
    console.log(`[CONFIG] Loaded subscriber user: ${username} (role: ${roleNames[role]}, maxConnections: ${maxConn})`);
  } else {
    console.warn(`[CONFIG] Invalid format for SUBSCRIBER_${subscriberIndex} (value redacted)`);
  }
  
  subscriberIndex++;
}

if (subscriberUsers.size === 0) {
  console.log('[CONFIG] No subscriber users configured');
} else {
  console.log(`[CONFIG] Default max connections per subscriber: ${subscriberConfig.defaultMaxConnections}`);
}

// Create Aedes MQTT broker with fixed 'broker' ID so built-in $SYS topics group cleanly under $SYS/broker/...
const aedes = new Aedes({ id: 'broker' });

// Rate limiting for failed connections
const rateLimiter = new RateLimiter(60000, 10, 300000);

// Abuse detection
const abuseDetector = new AbuseDetector(abuseConfig);

// $SYS telemetry collector (publishes retained metrics every sysIntervalMs for Role 1 ADMIN subscribers)
const sysMetrics = new SysMetricsCollector({
  aedes,
  rateLimiter,
  abuseDetector,
  subscriberAccounts: subscriberAccountsMeta,
  brokerVersion,
  brokerPublicKey: peerIdentity?.publicKeyHex,
  authorizedPeerKeysCount: peerConfig.authorizedPeerKeys?.size || 0,
  wsPort: WS_PORT,
  tcpEnabled: ENABLE_TCP,
  tcpPort: TCP_PORT,
  intervalMs: mqttConfig.sysIntervalMs,
  getPeerStats: () => (peerBridgeManager ? peerBridgeManager.getPeerStats() : {}),
});

// WeakMap caches keyed by packet.payload Buffer (survives Aedes `new Packet(packet)` cloning)
const parsedPayloadCache = new WeakMap<Buffer, any>();
const limitedPayloadCache = new WeakMap<Buffer, Buffer>();

function ensureBuffer(payload: string | Buffer): Buffer {
  return typeof payload === 'string' ? Buffer.from(payload, 'utf-8') : payload;
}

function getParsedJson(payload: string | Buffer): any {
  const buf = ensureBuffer(payload);
  let parsed = parsedPayloadCache.get(buf);
  if (parsed !== undefined) {
    return parsed;
  }
  parsed = JSON.parse(buf.toString('utf-8'));
  parsedPayloadCache.set(buf, parsed);
  return parsed;
}

// Silently drop a packet without disconnecting the publishing client or peer bridge.
function dropPacketSilently(packet: any, callback: (err?: Error | null) => void): void {
  packet.topic = '$drop';
  packet.retain = false;
  callback(null);
}

// Inbound peer rate limiting (token bucket per authenticated peer identity)
const peerRateBuckets = new Map<string, { tokens: number; lastRefill: number }>();

function checkPeerRateLimit(peerKey: string): boolean {
  const rate = peerConfig.peerRateLimitPerSec || 500;
  // Set burst capacity at or above PEER_QUEUE_MAX_SIZE so a full recovery backlog drain
  // is accepted without dropping packets, while sustained floods beyond `rate` are capped.
  const capacity = Math.max(peerConfig.maxQueueSize || 5000, rate * 2, 100);
  const now = Date.now();
  let bucket = peerRateBuckets.get(peerKey);
  if (!bucket) {
    if (peerRateBuckets.size >= 1000) {
      const oldest = peerRateBuckets.keys().next().value;
      if (oldest) peerRateBuckets.delete(oldest);
    }
    bucket = { tokens: capacity, lastRefill: now };
    peerRateBuckets.set(peerKey, bucket);
  } else {
    const elapsedSec = Math.max(0, (now - bucket.lastRefill) / 1000);
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSec * rate);
    bucket.lastRefill = now;
  }
  if (bucket.tokens < 1) {
    return false;
  }
  bucket.tokens -= 1;
  return true;
}

// Bounded cross-path deduplication cache for non-status telemetry (packets, neighbors, raw)
// Sized to at least PEER_QUEUE_TTL_MS (default 10m) so queued packets drained after an outage
// are still deduplicated for dual-connected observers.
const DEDUP_TTL_MS = Math.max(120_000, peerConfig.queueTtlMs || 600_000);
const DEDUP_MAX_ENTRIES = 100_000;
const seenPacketHashes = new Map<
  string,
  { timestamp: number; sourceId: string; forwardedByLocal: boolean }
>();

function checkCrossPathDuplicate(
  normalizedTopic: string,
  subtopic: string,
  payload: Buffer,
  sourceId: string,
  isPeerClient: boolean
): { duplicate: boolean; shouldForwardToPeers: boolean } {
  if (subtopic !== 'packets' && subtopic !== 'neighbors' && subtopic !== 'raw') {
    return { duplicate: false, shouldForwardToPeers: false };
  }
  const now = Date.now();
  const hash = createHash('sha256').update(normalizedTopic).update(':').update(payload).digest('hex');
  const existing = seenPacketHashes.get(hash);
  if (existing !== undefined && now - existing.timestamp < DEDUP_TTL_MS) {
    // If the duplicate arrived from a DIFFERENT client connection (e.g., dual-connected observer
    // or multi-peer path) or over a peer link, drop it for local subscribers.
    // However, if a peer copy arrived first (!existing.forwardedByLocal) and the direct local
    // observer copy arrives second (!isPeerClient), still forward the local observer copy to
    // outbound peers so backup paths (e.g., C -> B when A -> B is down) remain intact.
    if (isPeerClient || existing.sourceId !== sourceId) {
      let shouldForwardToPeers = false;
      if (!isPeerClient && !existing.forwardedByLocal) {
        existing.forwardedByLocal = true;
        shouldForwardToPeers = true;
      }
      return { duplicate: true, shouldForwardToPeers };
    }
  }

  if (!seenPacketHashes.has(hash) && seenPacketHashes.size >= DEDUP_MAX_ENTRIES) {
    let evicted = 0;
    for (const [k, entry] of seenPacketHashes) {
      if (now - entry.timestamp >= DEDUP_TTL_MS || evicted < 1000) {
        seenPacketHashes.delete(k);
        evicted++;
        if (seenPacketHashes.size < DEDUP_MAX_ENTRIES && now - entry.timestamp < DEDUP_TTL_MS) {
          break;
        }
      }
    }
  }

  seenPacketHashes.set(hash, {
    timestamp: now,
    sourceId,
    forwardedByLocal: !isPeerClient,
  });
  return { duplicate: false, shouldForwardToPeers: false };
}

// Throttle retained /internal publishes to once per 30s per observer (or immediately on status change)
const INTERNAL_PUBLISH_INTERVAL_MS = 30_000;
const lastInternalPublishMap = new Map<string, { timestamp: number; status: string }>();

function maybePublishInternalState(
  normalizedLocation: string,
  clientPublicKey: string,
  tokenPayload: any,
  trustState: any,
  logPrefix: string,
  forceImmediate = false
): void {
  if (!tokenPayload) return;

  const now = Date.now();
  const currentStatus = trustState?.status || 'allowed';
  const prev = lastInternalPublishMap.get(clientPublicKey);

  if (
    !forceImmediate &&
    prev &&
    prev.status === currentStatus &&
    now - prev.timestamp < INTERNAL_PUBLISH_INTERVAL_MS
  ) {
    return;
  }

  if (!lastInternalPublishMap.has(clientPublicKey) && lastInternalPublishMap.size >= 10_000) {
    const oldestKey = lastInternalPublishMap.keys().next().value;
    if (oldestKey) lastInternalPublishMap.delete(oldestKey);
  }
  lastInternalPublishMap.set(clientPublicKey, { timestamp: now, status: currentStatus });

  const internalTopic = `meshcore/${normalizedLocation}/${clientPublicKey}/internal`;
  let trustMetrics: any = null;

  if (trustState) {
    const clockQuality =
      trustState.clockTracking.erraticJumps.length === 0
        ? 'stable'
        : trustState.clockTracking.erraticJumps.length < 3
          ? 'syncing'
          : 'erratic';

    trustMetrics = {
      status: trustState.status,
      mutedUntil: trustState.mutedUntil ?? null,
      enforcement_enabled: abuseConfig.enforcementEnabled,
      totalPacketsReceived: trustState.totalPacketsReceived,
      totalPacketsSilenced: trustState.totalPacketsSilenced,
      duplicateCount: trustState.duplicateCount,
      anomalyCount: trustState.anomalyCount,
      anomalies: trustState.anomalies.slice(0, 20).map((a: any) => ({
        type: a.type,
        details: a.details,
        timestamp: a.timestamp,
      })),
      peakRateObserved: Math.round(trustState.peakRateObserved * 100) / 100,
      tokenBucket: {
        tokens: Math.round(trustState.tokenBucket.tokens * 10) / 10,
        capacity: trustState.tokenBucket.capacity,
      },
      iataTracking: {
        currentIata: trustState.currentIata,
        iataChangeCount24h: trustState.iataChangeCount24h,
        iataHistory: trustState.iataHistory.map((h: any) => h.iata),
      },
      clockTracking: {
        estimatedOffset: trustState.clockTracking.estimatedOffset
          ? Math.round(trustState.clockTracking.estimatedOffset / 1000)
          : undefined,
        erraticJumpCount: trustState.clockTracking.erraticJumps.length,
        lastDeviceTimestamp: trustState.clockTracking.lastDeviceTimestamp,
        clockQuality,
      },
      recentIPs: trustState.recentIPs.slice(0, 10).map((ip: any) => ({
        ip: ip.ip,
        connectionCount: ip.connectionCount,
        lastSeen: ip.lastSeen,
      })),
    };
  }

  const internalMessage = {
    origin_id: clientPublicKey,
    timestamp: now,
    jwt_payload: tokenPayload,
    trust_state: trustMetrics,
  };

  aedes.publish(
    {
      cmd: 'publish',
      topic: internalTopic,
      payload: Buffer.from(JSON.stringify(internalMessage)),
      qos: 0,
      dup: false,
      retain: true,
    },
    (err) => {
      if (err) {
        console.error(`${logPrefix} [INTERNAL] Failed to publish JWT payload:`, err);
      } else if (isDebug) {
        console.log(`${logPrefix} [INTERNAL] Published JWT payload -> ${internalTopic}`);
      }
    }
  );
}

// Helper to get client identifier for logging
function getClientLogPrefix(client: any): string {
  if (!client) return '[UNKNOWN]';
  
  const clientType = client.clientType;
  if (clientType === ClientType.PUBLISHER && client.publicKey) {
    return `[O:${client.publicKey.substring(0, 8)}]`;
  } else if (clientType === ClientType.PEER) {
    if (client.publicKey) {
      return `[P:${client.publicKey.substring(0, 8)}]`;
    }
    return `[P:${client.username || client.id}]`;
  } else if (clientType === ClientType.SUBSCRIBER && client.username) {
    return `[S:${client.username}]`;
  }
  return `[C:${client.id}]`;
}

// Authentication handler
aedes.authenticate = async (client, username, password, callback) => {
  const logPrefix = `[C:${client.id}]`;
  if (isDebug) {
    console.log(`${logPrefix} [AUTH] Authentication attempt - Username: ${username}`);
  }

  try {
    const usernameStr = username?.toString() || '';
    const passwordStr = password?.toString() || '';

    // Check if this is a subscriber or role-4 peer login
    if (subscriberUsers.has(usernameStr)) {
      const expectedPassword = subscriberUsers.get(usernameStr) || '';
      if (timingSafeCompare(passwordStr, expectedPassword)) {
        // Check connection limit before allowing
        const maxConn = subscriberMaxConnections.get(usernameStr) || subscriberConfig.defaultMaxConnections;
        const activeConns = subscriberActiveConnections.get(usernameStr) || new Set();
        
        if (activeConns.size >= maxConn) {
          console.log(`${logPrefix} [AUTH] ✗ Subscriber connection limit exceeded (${usernameStr}, ${activeConns.size}/${maxConn})`);
          sysMetrics.recordAuthFailure();
          callback(null, false);
          return;
        }
        
        // Track this connection
        activeConns.add(client.id);
        subscriberActiveConnections.set(usernameStr, activeConns);
        
        const role = subscriberRoles.get(usernameStr) || SubscriberRole.LIMITED;
        if (role === SubscriberRole.PEER) {
          console.log(`${logPrefix} [AUTH] ✓ Peer broker authenticated (${usernameStr}, connections: ${activeConns.size}/${maxConn})`);
          (client as any).clientType = ClientType.PEER;
          (client as any).username = usernameStr;
          (client as any).role = role;
        } else {
          console.log(`${logPrefix} [AUTH] ✓ Subscriber authenticated (${usernameStr}, role: ${role}, connections: ${activeConns.size}/${maxConn})`);
          (client as any).clientType = ClientType.SUBSCRIBER;
          (client as any).username = usernameStr;
          (client as any).role = role;
        }
        
        // Mark stream as authenticated
        const stream = (client as any).conn;
        if (stream && stream.clientIP) {
          stream.authenticated = true;
          stream.trustedPeer = role === SubscriberRole.PEER;
          stream.client = client;
        }
        
        callback(null, true);
      } else {
        console.log(`${logPrefix} [AUTH] ✗ Subscriber authentication failed - Invalid password`);
        sysMetrics.recordAuthFailure();
        callback(null, false);
      }
      return;
    }

    // Otherwise, check for JWT-based publisher or peer authentication
    // Username format: v1_{UPPERCASE_PUBLIC_KEY}
    if (!usernameStr.startsWith('v1_')) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid username format: ${usernameStr}`);
      sysMetrics.recordAuthFailure();
      callback(null, false);
      return;
    }

    const publicKey = usernameStr.substring(3).toUpperCase().trim();
    
    // Validate public key format (should be 64 hex characters)
    if (!/^[0-9A-F]{64}$/i.test(publicKey)) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid public key format: ${publicKey}`);
      sysMetrics.recordAuthFailure();
      callback(null, false);
      return;
    }

    if (!passwordStr || passwordStr.length === 0) {
      console.log(`${logPrefix} [AUTH] ✗ No password provided`);
      sysMetrics.recordAuthFailure();
      callback(null, false);
      return;
    }

    // Verify the auth token using meshcore-decoder (never log raw passwordStr)
    const tokenPayload = await verifyAuthToken(passwordStr, publicKey);

    if (!tokenPayload) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid token signature for public key: ${publicKey.substring(0, 8)}...`);
      sysMetrics.recordAuthFailure();
      callback(null, false);
      return;
    }
    
    // Validate audience claim if configured
    if (EXPECTED_AUDIENCE && tokenPayload.aud !== EXPECTED_AUDIENCE) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid audience: ${tokenPayload.aud} (expected: ${EXPECTED_AUDIENCE})`);
      sysMetrics.recordAuthFailure();
      callback(null, false);
      return;
    }

    const shortKey = publicKey.substring(0, 8);
    const stream = (client as any).conn;

    // Check if this public key is an authorized peer broker (AUTHORIZED_PEERS)
    if (peerConfig.authorizedPeerKeys && peerConfig.authorizedPeerKeys.has(publicKey)) {
      console.log(`[P:${shortKey}] [AUTH] ✓ Peer broker authenticated via Ed25519 JWT${tokenPayload.aud ? ` [aud: ${tokenPayload.aud}]` : ''}`);
      (client as any).publicKey = publicKey;
      (client as any).tokenPayload = tokenPayload;
      (client as any).clientType = ClientType.PEER;

      if (stream && stream.clientIP) {
        stream.authenticated = true;
        stream.trustedPeer = true;
        stream.client = client;
      }

      callback(null, true);
      return;
    }
    
    console.log(`[O:${shortKey}] [AUTH] ✓ Publisher authenticated${tokenPayload.aud ? ` [aud: ${tokenPayload.aud}]` : ''}`);
    // Store the public key and client type with the client for later use
    (client as any).publicKey = publicKey;
    (client as any).tokenPayload = tokenPayload;
    (client as any).clientType = ClientType.PUBLISHER;
    
    // Mark stream as authenticated
    if (stream && stream.clientIP) {
      stream.authenticated = true;
      stream.client = client;
    }
    
    // Initialize abuse detection tracking
    const clientIP = stream?.clientIP;
    abuseDetector.initializeClient(publicKey, `v1_${publicKey}`, clientIP);
    
    callback(null, true);
  } catch (error) {
    console.error(`${logPrefix} [AUTH] Error during authentication:`, error);
    sysMetrics.recordAuthFailure();
    callback(null, false);
  }
};

// Authorization handler (control topic access)
// Deferring rawCallback via process.nextTick ensures mqtt-packet's synchronous _newPacket()
// loop always finishes resetting parser state before Aedes invokes client._nextBatch(),
// even when zero subscribers are connected.
aedes.authorizePublish = (client, packet, rawCallback) => {
  const callback = (err?: Error | null) => {
    process.nextTick(rawCallback, err ?? null);
  };

  if (!client) {
    callback(new Error('No client'));
    return;
  }
  
  const logPrefix = getClientLogPrefix(client);
  const clientType = (client as any).clientType;

  // Enforce maximum packet payload size to prevent event loop freezes and memory exhaustion
  if (packet.payload && packet.payload.length > mqttConfig.maxPacketBytes) {
    console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (payload size ${packet.payload.length}B exceeds limit ${mqttConfig.maxPacketBytes}B)`);
    sysMetrics.recordUnauthorizedPublish();
    callback(new Error(`Payload size exceeds maximum allowed size of ${mqttConfig.maxPacketBytes} bytes`));
    return;
  }
  
  // Important: Strip retain flag from /status messages to prevent stale data on ingestor restart
  // LWT (offline) messages are also STATUS messages and should NOT be retained
  if (packet.topic.endsWith('/status') && packet.retain) {
    if (isDebug) {
      console.log(`${logPrefix} [AUTHZ] Stripping retain flag from STATUS message -> ${packet.topic}`);
    }
    packet.retain = false;
  }
  
  // Subscriber clients cannot publish (subscribe-only)
  if (clientType === ClientType.SUBSCRIBER) {
    const role = (client as any).role || SubscriberRole.LIMITED;
    
    // Admin subscribers (role 1) can publish empty retained messages to delete them
    if (role === SubscriberRole.ADMIN && packet.retain && packet.payload.length === 0) {
      console.log(`${logPrefix} [AUTHZ] ✓ Admin delete authorized -> ${packet.topic}`);
      callback(null);
      return;
    }
    
    // Admin subscribers (role 1) can publish to serial/commands topics for remote serial access
    // Topic format: meshcore/{IATA}/{PUBLIC_KEY}/serial/commands
    if (role === SubscriberRole.ADMIN && packet.topic.endsWith('/serial/commands')) {
      const parts = packet.topic.split('/');
      // Validate: meshcore / IATA / PUBLIC_KEY / serial / commands (5 parts)
      if (parts.length === 5 && parts[0] === 'meshcore' && parts[3] === 'serial') {
        const iata = parts[1];
        const publicKey = parts[2];
        // Basic format validation (real validation happens at meshcoretomqtt via JWT)
        const isValidIata = /^[A-Z]{3}$/i.test(iata) || iata.toLowerCase() === 'test';
        const isValidPubKey = /^[0-9A-Fa-f]{64}$/.test(publicKey);
        if (isValidIata && isValidPubKey) {
          console.log(`${logPrefix} [AUTHZ] ✓ Admin serial command authorized -> ${packet.topic}`);
          callback(null);
          return;
        }
      }
      console.log(`${logPrefix} [AUTHZ] ✗ Serial command denied (invalid topic format) -> ${packet.topic}`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Invalid serial/commands topic format'));
      return;
    }

    // Silently ignore Mosquitto bridge state notifications ($SYS/broker/connection/<id>/state)
    // so Mosquitto pull bridges without `notifications false` do not get disconnected
    if (packet.topic.startsWith('$SYS/broker/connection/')) {
      if (isDebug) {
        console.log(`${logPrefix} [AUTHZ] ✗ Ignored bridge state notification from subscriber -> ${packet.topic}`);
      }
      dropPacketSilently(packet, callback);
      return;
    }
    
    console.log(`${logPrefix} [AUTHZ] ✗ Publish denied (subscriber) -> ${packet.topic}`);
    sysMetrics.recordUnauthorizedPublish();
    callback(new Error('Subscriber clients are subscribe-only'));
    return;
  }

  // Inbound Peer broker clients (ClientType.PEER)
  if (clientType === ClientType.PEER) {
    const peerKey = (client as any).publicKey || (client as any).username || client.id;
    if (!checkPeerRateLimit(peerKey)) {
      if (isDebug) {
        console.log(
          `${logPrefix} [RATE_LIMIT] Dropped peer packet exceeding PEER_RATE_LIMIT_PER_SEC (${peerConfig.peerRateLimitPerSec}/s)`
        );
      }
      sysMetrics.recordPeerRateLimited(client);
      dropPacketSilently(packet, callback);
      return;
    }

    const validation = validatePeerPacket(packet.topic, packet.payload, isValidIATACode);
    if (!validation.valid) {
      if (isDebug) {
        console.log(`${logPrefix} [AUTHZ] ✗ Peer publish dropped -> ${packet.topic} (${validation.error})`);
      }
      sysMetrics.recordUnauthorizedPublish();
      sysMetrics.recordInboundPeerInvalid(client);
      dropPacketSilently(packet, callback);
      return;
    }

    const locationCode = validation.normalizedLocation!;
    packet.topic = validation.normalizedTopic!;
    const subtopic = validation.subtopic!;
    const payloadBuf = ensureBuffer(packet.payload);

    // Deduplicate cross-path packets (e.g., dual-connected observers or multi-hop topologies)
    const dedup = checkCrossPathDuplicate(packet.topic, subtopic, payloadBuf, client.id, true);
    if (dedup.duplicate) {
      if (isDebug) {
        console.log(`${logPrefix} [DEDUP] Dropped duplicate peer packet -> ${packet.topic}`);
      }
      sysMetrics.recordDuplicateFiltered();
      sysMetrics.recordInboundPeerDuplicate(client);
      dropPacketSilently(packet, callback);
      return;
    }

    if (validation.parsedMessage && validation.originId) {
      parsedPayloadCache.set(payloadBuf, validation.parsedMessage);
      (packet as any)._parsedJson = validation.parsedMessage;

      const originKey = validation.originId;
      let trustState = abuseDetector.getClientStats(originKey);
      if (!trustState) {
        abuseDetector.initializeClient(originKey, `v1_${originKey}`);
        trustState = abuseDetector.getClientStats(originKey);
      }

      if (trustState) {
        trustState.currentIata = locationCode;
        const allowed = abuseDetector.recordPacket(
          { publicKey: originKey } as any,
          packet,
          validation.parsedMessage,
          { fromPeer: true }
        );
        if (!allowed) {
          if (isDebug) {
            console.log(`${logPrefix} [ABUSE] Silenced peer-forwarded packet from muted observer ${originKey.substring(0, 8)}`);
          }
          dropPacketSilently(packet, callback);
          return;
        }
      }
    }

    sysMetrics.recordInboundPeerPublish(client, subtopic, payloadBuf.length);

    if (isDebug) {
      console.log(`${logPrefix} [AUTHZ] ✓ Peer publish authorized -> ${packet.topic}`);
    }
    callback(null);
    return;
  }
  
  // Publisher clients can only publish to meshcore/* topics
  if (clientType === ClientType.PUBLISHER) {
    if (!packet.topic.startsWith('meshcore/')) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (not meshcore/*)`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Publishers can only publish to meshcore/* topics'));
      return;
    }

    // Validate topic format
    // Required format: meshcore/{IATA}/{PUBLIC_KEY}/subtopic
    const topicParts = packet.topic.split('/').map(part => part.trim());
    if (topicParts.length < 4) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (must be meshcore/IATA/PUBKEY/subtopic format)`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Topic must be meshcore/IATA/PUBKEY/subtopic format (4 parts required)'));
      return;
    }
    
    const locationCode = topicParts[1].trim();
    const iataRegex = /^[A-Z]{3}$/;
    
    // Reject XXX explicitly (default placeholder value)
    if (locationCode === 'XXX') {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (XXX not valid, configure actual IATA)`);
      console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid location code: XXX`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('XXX is a placeholder - please configure your actual IATA location code'));
      client.close();
      return;
    }
    
    // Check if this is the special "test" region and normalize it to lowercase
    const isTestRegion = locationCode.toLowerCase() === 'test';
    
    if (!isTestRegion) {
      // First check format (must be 3 uppercase letters, no normalization)
      if (!iataRegex.test(locationCode)) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid format)`);
        console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid location format: "${locationCode}"`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('Location must be exactly 3 uppercase letters (e.g., SEA, PDX, BOS) or "test"'));
        client.close();
        return;
      }
      
      // Then check if it's a valid IATA code
      if (!isValidIATACode(locationCode)) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid IATA)`);
        console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid IATA code: "${locationCode}"`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('Location must be a valid IATA international airport code or "test"'));
        client.close();
        return;
      }
    }
    
    // Validate public key in topic (required - topicParts[2])
    const topicPublicKey = topicParts[2].trim().toUpperCase();
    
    // Validate it looks like a public key (64 hex chars)
    if (!/^[0-9A-F]{64}$/i.test(topicPublicKey)) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid pubkey format)`);
      console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid public key format in topic`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Public key in topic must be 64 hex characters'));
      client.close();
      return;
    }
    
    // Validate topic public key matches authenticated client
    const clientPublicKey = (client as any).publicKey.toUpperCase();
    if (topicPublicKey !== clientPublicKey) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (pubkey mismatch)`);
      console.log(`${logPrefix} [DISCONNECT] Closing client - Public key mismatch`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Public key in topic must match authenticated public key'));
      client.close();
      return;
    }

    const subtopic = topicParts.slice(3).join('/');

    // Protect /internal subtopic: only the broker may publish to /internal; direct client publishing is dropped silently
    if (subtopic === 'internal' || subtopic.startsWith('internal/') || subtopic.includes('/internal')) {
      if (isDebug) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish dropped -> ${packet.topic} (clients cannot publish to /internal directly)`);
      }
      sysMetrics.recordUnauthorizedPublish();
      dropPacketSilently(packet, callback);
      return;
    }

    // Enforce subtopic allowlist without disconnecting the client
    if (!ALLOWED_PUBLISHER_SUBTOPICS.has(subtopic)) {
      if (isDebug) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish dropped -> ${packet.topic} (disallowed subtopic: ${subtopic})`);
      }
      sysMetrics.recordUnauthorizedPublish();
      dropPacketSilently(packet, callback);
      return;
    }

    // Normalize the topic to UPPERCASE for IATA codes and public key component
    const normalizedLocation = isTestRegion ? 'test' : locationCode.toUpperCase();
    const normalizedTopic = `meshcore/${normalizedLocation}/${clientPublicKey}/${subtopic}`;
    (client as any).currentIata = normalizedLocation;
    
    if (packet.topic !== normalizedTopic) {
      if (isDebug) {
        console.log(`${logPrefix} [AUTHZ] Normalized topic: ${packet.topic} -> ${normalizedTopic}`);
      }
      packet.topic = normalizedTopic;
    }

    // Special handling for serial/responses - payload is a JWT string, not JSON
    if (subtopic === 'serial/responses') {
      const payload = packet.payload.toString('utf-8');
      const jwtParts = payload.split('.');
      if (jwtParts.length !== 3) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JWT format)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('serial/responses payload must be a valid JWT'));
        return;
      }
      const base64urlRegex = /^[A-Za-z0-9_-]+$/;
      if (!jwtParts.every(part => base64urlRegex.test(part))) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JWT encoding)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('serial/responses payload must be a valid JWT'));
        return;
      }
      if (isDebug) {
        console.log(`${logPrefix} [AUTHZ] ✓ Publish authorized (serial response) -> ${packet.topic}`);
      }
      callback(null);
      return;
    }

    // Validate that the message contains origin_id matching the authenticated public key
    try {
      const message = getParsedJson(packet.payload);
      (packet as any)._parsedJson = message;
      
      if (!message || typeof message.origin_id !== 'string' || !message.origin_id) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (missing origin_id)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('Message must contain origin_id field'));
        return;
      }
      
      const messageOriginId = message.origin_id.toUpperCase();
      const normalizedClientKey = clientPublicKey.toUpperCase();
      
      if (messageOriginId !== normalizedClientKey) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (origin_id mismatch)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('origin_id must match authenticated public key'));
        return;
      }

      // Track with abuse detector and enforce 4-hour temporary mute timeout if enabled
      const trustState = abuseDetector.getClientStats(clientPublicKey);
      let allowed = true;
      if (trustState) {
        const prevStatus = trustState.status;
        abuseDetector.checkIataChange(trustState, normalizedLocation);
        allowed = abuseDetector.recordPacket(client, packet, message);

        if (prevStatus !== trustState.status) {
          maybePublishInternalState(
            normalizedLocation,
            clientPublicKey,
            (client as any).tokenPayload,
            trustState,
            logPrefix,
            true
          );
        }
      }

      if (!allowed) {
        if (isDebug) {
          console.log(`${logPrefix} [ABUSE] Silenced packet from muted publisher -> ${packet.topic}`);
        }
        dropPacketSilently(packet, callback);
        return;
      }

      // Check cross-path deduplication (drops for local subscribers if already received from a peer or second connection,
      // while preserving outbound peer forwarding if the prior copy came from a peer)
      const payloadBuf = ensureBuffer(packet.payload);
      const dedup = checkCrossPathDuplicate(packet.topic, subtopic, payloadBuf, client.id, false);
      if (dedup.duplicate) {
        if (dedup.shouldForwardToPeers && peerBridgeManager) {
          peerBridgeManager.forwardLocalPacket({
            topic: packet.topic,
            payload: payloadBuf,
            qos: packet.qos,
            retain: packet.retain,
          });
        }
        if (isDebug) {
          console.log(`${logPrefix} [DEDUP] Dropped cross-path duplicate packet -> ${packet.topic}`);
        }
        sysMetrics.recordDuplicateFiltered();
        dropPacketSilently(packet, callback);
        return;
      }
      
      if (isDebug) {
        console.log(`${logPrefix} [AUTHZ] ✓ Publish authorized -> ${packet.topic}`);
      }
      
      // Publish JWT payload to /internal topic (throttled to once per 30s or status change)
      maybePublishInternalState(
        normalizedLocation,
        clientPublicKey,
        (client as any).tokenPayload,
        trustState,
        logPrefix,
        false
      );
      
      callback(null);
    } catch (error) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JSON or validation error)`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Invalid message format or origin_id validation failed'));
    }
    return;
  }
  
  // Unknown client type
  console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (unknown client type)`);
  sysMetrics.recordUnauthorizedPublish();
  callback(new Error('Unknown client type'));
};

aedes.authorizeSubscribe = (client, subscription, callback) => {
  if (!client) {
    callback(new Error('No client'));
    return;
  }

  // Never allow subscriptions to internal silent-drop sink topic
  if (subscription.topic === '$drop' || subscription.topic.startsWith('$drop/')) {
    callback(new Error('Cannot subscribe to internal drop topic'));
    return;
  }
  
  const logPrefix = getClientLogPrefix(client);
  const clientType = (client as any).clientType;

  // Peer clients are publish-only
  if (clientType === ClientType.PEER) {
    console.log(`${logPrefix} [AUTHZ] ✗ Subscribe denied (peer) -> ${subscription.topic}`);
    callback(new Error('Peer clients are publish-only'));
    return;
  }
  
  // Publisher clients cannot subscribe (publish-only) - EXCEPT their own serial/commands topic
  if (clientType === ClientType.PUBLISHER) {
    if (subscription.topic.endsWith('/serial/commands')) {
      const parts = subscription.topic.split('/');
      if (parts.length === 5 && parts[0] === 'meshcore' && parts[3] === 'serial') {
        const topicPublicKey = parts[2].toUpperCase();
        const clientPublicKey = ((client as any).publicKey || '').toUpperCase();
        if (topicPublicKey === clientPublicKey && clientPublicKey.length === 64) {
          console.log(`${logPrefix} [AUTHZ] ✓ Subscribe authorized (own serial/commands) -> ${subscription.topic}`);
          callback(null, subscription);
          return;
        }
      }
    }
    console.log(`${logPrefix} [AUTHZ] ✗ Subscribe denied (publisher) -> ${subscription.topic}`);
    console.log(`${logPrefix} [DISCONNECT] Closing client - Publishers cannot subscribe`);
    callback(new Error('Publisher clients are publish-only'));
    client.close();
    return;
  }
  
  // Subscriber clients can subscribe to any topic (they're listeners)
  if (clientType === ClientType.SUBSCRIBER) {
    console.log(`${logPrefix} [AUTHZ] ✓ Subscribe authorized -> ${subscription.topic}`);
    callback(null, subscription);
    return;
  }
  
  // Unknown client type
  console.log(`${logPrefix} [AUTHZ] ✗ Subscribe denied -> ${subscription.topic} (unknown client type)`);
  callback(new Error('Unknown client type'));
};

// Track last seen status timestamp per origin_id to prevent race conditions (bounded to 10,000 origins)
const lastStatusTimestamps = new Map<string, number>();
const MAX_STATUS_ORIGINS = 10_000;
const MAX_FUTURE_STATUS_SKEW_MS = 60_000;

// Authorization handler for forwarding messages to subscribers (filter sensitive data)
aedes.authorizeForward = (client, packet) => {
  if (packet.topic === '$drop') {
    return null;
  }

  if (!client) {
    return packet;
  }
  
  const clientType = (client as any).clientType;
  const role = (client as any).role;
  
  // Block $SYS/* messages for non-admin subscribers (only role 1 can see system topics)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.startsWith('$SYS/')) {
      return null;
    }
  }
  
  // Critical: Block /internal topics for non-admin subscribers (contains PII)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.includes('/internal')) {
      return null;
    }
  }
  
  // Block /serial/* topics for non-admin subscribers (remote serial access is admin-only)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.includes('/serial/')) {
      return null;
    }
  }
  
  // Prevent stale status messages from overwriting newer ones (LWT race condition)
  if (packet.topic.endsWith('/status') && packet.payload && packet.payload.length > 0) {
    try {
      const message = getParsedJson(packet.payload);
      const originId = message?.origin_id;
      const rawTimestamp = message?.timestamp ? new Date(message.timestamp).getTime() : 0;
      
      if (originId && rawTimestamp && !isNaN(rawTimestamp)) {
        // Clamp future timestamps to prevent future-timestamp poisoning DoS
        const effectiveTimestamp = Math.min(rawTimestamp, Date.now() + MAX_FUTURE_STATUS_SKEW_MS);
        const lastTimestamp = lastStatusTimestamps.get(originId) || 0;
        
        if (effectiveTimestamp < lastTimestamp) {
          if (isDebug) {
            console.log(`[FILTER] Blocking stale status message for ${originId.substring(0, 8)} (${new Date(effectiveTimestamp).toISOString()} < ${new Date(lastTimestamp).toISOString()})`);
          }
          sysMetrics.recordStaleStatusFiltered();
          return null;
        }
        
        if (!lastStatusTimestamps.has(originId) && lastStatusTimestamps.size >= MAX_STATUS_ORIGINS) {
          const oldestKey = lastStatusTimestamps.keys().next().value;
          if (oldestKey) lastStatusTimestamps.delete(oldestKey);
        }
        lastStatusTimestamps.set(originId, effectiveTimestamp);
      }
    } catch (error) {
      if (isDebug) {
        console.debug(`[FILTER] Failed to parse status message for timestamp check:`, error);
      }
    }
  }
  
  // Only filter for LIMITED role subscribers (role 3), caching the filtered Buffer in WeakMap
  if (clientType === ClientType.SUBSCRIBER && role === SubscriberRole.LIMITED) {
    const isStatus = packet.topic.endsWith('/status');
    const isPackets = !isStatus && packet.topic.endsWith('/packets');

    if ((isStatus || isPackets) && packet.payload && packet.payload.length > 0) {
      const payloadBuf = ensureBuffer(packet.payload);
      const cachedPayload = limitedPayloadCache.get(payloadBuf);
      if (cachedPayload !== undefined) {
        return cachedPayload === payloadBuf ? packet : { ...packet, payload: cachedPayload };
      }

      try {
        const message = getParsedJson(payloadBuf);
        if (message && typeof message === 'object') {
          if (isStatus) {
            if (
              message.stats !== undefined ||
              message.model !== undefined ||
              message.firmware_version !== undefined
            ) {
              const copy = { ...message };
              delete copy.stats;
              delete copy.model;
              delete copy.firmware_version;
              const filteredBuf = Buffer.from(JSON.stringify(copy));
              limitedPayloadCache.set(payloadBuf, filteredBuf);
              return { ...packet, payload: filteredBuf };
            }
          } else if (isPackets) {
            if (
              message.SNR !== undefined ||
              message.RSSI !== undefined ||
              message.score !== undefined
            ) {
              const copy = { ...message };
              delete copy.SNR;
              delete copy.RSSI;
              delete copy.score;
              const filteredBuf = Buffer.from(JSON.stringify(copy));
              limitedPayloadCache.set(payloadBuf, filteredBuf);
              return { ...packet, payload: filteredBuf };
            }
          }
        }
        // Cache original payload reference when no fields needed stripping
        limitedPayloadCache.set(payloadBuf, payloadBuf);
      } catch (error) {
        if (isDebug) {
          console.debug(`[FILTER] Failed to parse message for Role 3 filtering:`, error);
        }
      }
    }
  }
  
  return packet;
};

// Event handlers
aedes.on('client', (client) => {
  // Link stream to client if available
  (client as any).stream = (client as any).conn;
  if ((client as any).conn) {
    ((client as any).conn as any).client = client;
  }
  
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [CLIENT] Connected (IP: ${(client as any).conn?.clientIP || 'unknown'})`);
  
  // Track when this client connected for disconnect timing and $SYS metrics
  (client as any).connectedAt = Date.now();
  sysMetrics.recordClientConnected((aedes as any).connectedClients || 1);
  
  // Hook into the client's stream close event when debug logging is enabled
  const stream = (client as any).stream;
  if (stream && isDebug) {
    const originalClose = stream.close?.bind(stream);
    const originalDestroy = stream.destroy?.bind(stream);
    
    (stream as any).close = function(...args: any[]) {
      console.log(`${logPrefix} [STREAM] close() called (server-initiated close)`);
      if (originalClose) originalClose(...args);
    };
    
    (stream as any).destroy = function(...args: any[]) {
      console.log(`${logPrefix} [STREAM] destroy() called - error: ${args[0]?.message || 'none'}`);
      if (originalDestroy) originalDestroy(...args);
    };
  }
});

aedes.on('clientDisconnect', (client) => {
  const logPrefix = getClientLogPrefix(client);
  const connectedAt = (client as any).connectedAt;
  const duration = connectedAt ? Math.round((Date.now() - connectedAt) / 1000) : 'unknown';
  
  console.log(`${logPrefix} [CLIENT] Disconnected (connected for ${duration}s)`);
  sysMetrics.recordClientDisconnected();
  
  if (client) {
    if (isDebug) {
      console.log(`${logPrefix} [CLIENT] Disconnect details - clientType: ${(client as any).clientType}, publicKey: ${(client as any).publicKey?.substring(0, 8)}`);
    }
    
    // Clean up subscriber/peer account connection tracking
    const clientType = (client as any).clientType;
    const username = (client as any).username;
    if ((clientType === ClientType.SUBSCRIBER || clientType === ClientType.PEER) && username) {
      const activeConns = subscriberActiveConnections.get(username);
      if (activeConns) {
        activeConns.delete(client.id);
        const maxConn = subscriberMaxConnections.get(username) || subscriberConfig.defaultMaxConnections;
        console.log(`${logPrefix} [CLIENT] Connection removed (${username}, connections: ${activeConns.size}/${maxConn})`);
      }
    }
  }
});

aedes.on('publish', (packet, client) => {
  // Ignore silently dropped packets
  if (packet.topic === '$drop') {
    return;
  }

  sysMetrics.recordPublish(packet.topic, packet.payload.length, Boolean(packet.retain), Boolean(client));

  // Strict Origin-Only Peer Forwarding:
  // ONLY forward packets published directly by local observers (ClientType.PUBLISHER)
  // NEVER forward packets received from another peer broker (ClientType.PEER)
  if (
    peerBridgeManager &&
    client &&
    (client as any).clientType === ClientType.PUBLISHER
  ) {
    peerBridgeManager.forwardLocalPacket(packet);
  }

  if (isDebug) {
    if (client) {
      const logPrefix = getClientLogPrefix(client);
      console.log(`${logPrefix} [PUBLISH] ${packet.topic} (${packet.payload.length} bytes)`);
    } else if (!packet.topic.startsWith('$SYS/')) {
      console.log(`[PUBLISH] Internal -> ${packet.topic} (${packet.payload.length} bytes)`);
    }
  }
});

aedes.on('subscribe', (subscriptions, client) => {
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [SUBSCRIBE] Attempting to subscribe to: ${subscriptions.map(s => s.topic).join(', ')}`);
});

aedes.on('clientError', (client, err) => {
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [ERROR] Client error: ${err.message}`);
});

// Create HTTP server for WebSocket
const httpServer = createServer((req, res) => {
  const clientIP = getClientIP(req);

  // Reject HTTP requests from blocked IPs
  if (rateLimiter.isBlocked(clientIP)) {
    console.log(`[RATE_LIMIT] Rejecting HTTP request from blocked IP: ${clientIP}`);
    req.socket.destroy();
    return;
  }

  // If this is not a WebSocket upgrade request, handle standard HTTP request
  if (!req.headers.upgrade || req.headers.upgrade.toLowerCase() !== 'websocket') {
    const reqPath = (req.url || '/').split('?')[0];
    if (reqPath === '/health' || reqPath === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'MeshCore MQTT Broker' }));
      return;
    }

    if (HTTP_REDIRECT_URL) {
      if (isDebug) {
        console.log(`[HTTP] Non-WebSocket request from ${clientIP}, redirecting to ${HTTP_REDIRECT_URL}`);
      }
      res.writeHead(302, { 'Location': HTTP_REDIRECT_URL });
      res.end();
      return;
    }

    if (isDebug) {
      console.log(`[HTTP] Non-WebSocket status request from ${clientIP}`);
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'MeshCore MQTT Broker' }));
    return;
  }
});

// Create WebSocket server with bounded maxPayload to prevent unauthenticated memory exhaustion
const wsServer = new WebSocketServer({
  server: httpServer,
  maxPayload: 1024 * 1024 // 1MB max frame size
});

wsServer.on('connection', (ws, req) => {
  try {
    const clientIP = getClientIP(req);
    
    // Check if IP is blocked
    if (rateLimiter.isBlocked(clientIP)) {
      console.log(`[RATE_LIMIT] Rejecting connection from blocked IP: ${clientIP}`);
      ws.terminate();
      return;
    }
    
    if (isDebug) {
      console.log(`[WEBSOCKET] New WebSocket connection from ${clientIP}`);
    }
  
    // Enable WebSocket ping/pong to keep connection alive
    ws.on('ping', (data) => {
      if (isDebug) {
        console.log(`[WEBSOCKET] Received WebSocket PING from ${clientIP}, sending PONG`);
      }
      ws.pong(data);
    });
    
    ws.on('pong', () => {
      if (isDebug) {
        console.log(`[WEBSOCKET] Received WebSocket PONG from ${clientIP}`);
      }
    });
    
    // Handle WebSocket errors
    ws.on('error', (error) => {
      console.error('[WEBSOCKET] Error from %s: %s', clientIP, error.message);
    });
    
    // Create per-connection MQTT packet validator with headroom for topic and header bytes
    const packetValidator = new MqttStreamValidator(mqttConfig.maxPacketBytes + 4096);

    // Create a duplex stream from the WebSocket
    const stream = new Duplex({
      read() {
        if (ws.readyState === ws.OPEN) {
          ws.resume();
        }
      },
      write(chunk, encoding, callback) {
        if (ws.readyState === ws.OPEN) {
          if (isDebug && chunk instanceof Buffer && chunk.length >= 2 && chunk[0] === 0xD0) {
            const clientInfo = (stream as any).client;
            if (clientInfo) {
              const logPrefix = getClientLogPrefix(clientInfo);
              console.log(`${logPrefix} [MQTT] Sending PINGRESP (PONG) to client`);
            } else {
              console.log(`[MQTT] Sending PINGRESP (PONG) to unauthenticated client`);
            }
          }
          
          ws.send(chunk, (error) => {
            if (error && (error as any).code !== 'EPIPE') {
              const clientInfo = (stream as any).client;
              if (clientInfo) {
                const logPrefix = getClientLogPrefix(clientInfo);
                console.error(`${logPrefix} [WEBSOCKET] Send error:`, error);
              } else {
                console.error('[WEBSOCKET] Send error:', error);
              }
            }
            callback(error);
          });
        } else {
          callback(new Error('WebSocket not open'));
        }
      }
    });

    // Forward WebSocket messages to the stream with validation and backpressure handling
    ws.on('message', (data) => {
      const buf = Buffer.isBuffer(data)
        ? data
        : Array.isArray(data)
          ? Buffer.concat(data)
          : Buffer.from(data);

      const valErr = packetValidator.processChunk(buf);
      if (valErr) {
        const clientInfo = (stream as any).client;
        const logPrefix = clientInfo ? getClientLogPrefix(clientInfo) : '[C:unauth]';
        console.log(`${logPrefix} [MQTT] ✗ Connection dropped: ${valErr.message} from ${clientIP}`);
        ws.terminate();
        stream.destroy();
        return;
      }

      if (isDebug && buf.length >= 2 && buf[0] === 0xC0) {
        const clientInfo = (stream as any).client;
        if (clientInfo) {
          const logPrefix = getClientLogPrefix(clientInfo);
          console.log(`${logPrefix} [MQTT] Received PINGREQ (PING) from client`);
        } else {
          console.log('[MQTT] Received PINGREQ (PING) from unauthenticated client');
        }
      }
      const canAcceptMore = stream.push(buf);
      if (!canAcceptMore && ws.readyState === ws.OPEN) {
        ws.pause();
      }
    });

    // Store client IP and transport on stream for logging and $SYS metrics
    (stream as any).clientIP = clientIP;
    (stream as any).transport = 'websocket';
    (stream as any).authenticated = false;
    
    // Handle WebSocket close
    ws.on('close', (code, reason) => {
      const clientInfo = (stream as any).client;
      const wasAuthenticated = (stream as any).authenticated;
      const isTrustedPeer = Boolean((stream as any).trustedPeer);
      const hasValidAuth = clientInfo && (clientInfo as any).clientType;
      
      if (hasValidAuth) {
        if (isDebug) {
          const logPrefix = getClientLogPrefix(clientInfo);
          console.log(`${logPrefix} [WEBSOCKET] Connection closed from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
        }
      } else {
        console.log(`[C:${clientInfo?.id || 'null'}] [WEBSOCKET] Connection closed (unauthenticated) from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
        
        if (!wasAuthenticated && !isTrustedPeer) {
          const blocked = rateLimiter.recordFailure(clientIP);
          if (blocked) {
            console.log(`[RATE_LIMIT] IP ${clientIP} has been blocked`);
          }
        }
      }
      if (!stream.destroyed) {
        stream.push(null);
      }
    });

    // Handle stream end
    stream.on('end', () => {
      if (isDebug) {
        const clientInfo = (stream as any).client;
        if (clientInfo) {
          const logPrefix = getClientLogPrefix(clientInfo);
          console.log(`${logPrefix} [STREAM] Stream ended, closing WebSocket`);
        } else {
          console.log('[STREAM] Stream ended (unauthenticated), closing WebSocket');
        }
      }
      ws.close();
    });

    // Pass the stream to Aedes
    aedes.handle(stream);
  } catch (error) {
    console.error('[WEBSOCKET] Error handling connection:', error);
    try {
      ws.terminate();
    } catch (e) {
      // Ignore errors when terminating
    }
  }
});

// Create optional TCP server for raw MQTT connections (e.g. Mosquitto bridge)
let tcpServer: any = null;
if (ENABLE_TCP) {
  tcpServer = createTcpServer((socket: any) => {
    const rawIP = socket.remoteAddress || 'unknown';
    const clientIP = rawIP.startsWith('::ffff:') ? rawIP.slice(7) : rawIP;

    if (rateLimiter.isBlocked(clientIP)) {
      console.log(`[RATE_LIMIT] Rejecting TCP connection from blocked IP: ${clientIP}`);
      socket.destroy();
      return;
    }

    if (isDebug) {
      console.log(`[TCP] New TCP MQTT connection from ${clientIP}`);
    }
    (socket as any).clientIP = clientIP;
    (socket as any).transport = 'tcp';
    (socket as any).authenticated = false;

    const packetValidator = new MqttStreamValidator(mqttConfig.maxPacketBytes + 4096);
    socket.on('data', (chunk: Buffer) => {
      const valErr = packetValidator.processChunk(chunk);
      if (valErr) {
        const clientInfo = (socket as any).client;
        const logPrefix = clientInfo ? getClientLogPrefix(clientInfo) : '[C:unauth]';
        console.log(`${logPrefix} [TCP] ✗ Connection dropped: ${valErr.message} from ${clientIP}`);
        socket.destroy();
      }
    });

    socket.on('error', (error: Error) => {
      console.error('[TCP] Error from %s: %s', clientIP, error.message);
    });

    socket.on('close', () => {
      const clientInfo = (socket as any).client;
      const wasAuthenticated = (socket as any).authenticated;
      const isTrustedPeer = Boolean((socket as any).trustedPeer);
      const hasValidAuth = clientInfo && (clientInfo as any).clientType;

      if (hasValidAuth) {
        if (isDebug) {
          const logPrefix = getClientLogPrefix(clientInfo);
          console.log(`${logPrefix} [TCP] Connection closed from ${clientIP}`);
        }
      } else {
        console.log(`[C:${clientInfo?.id || 'null'}] [TCP] Connection closed (unauthenticated) from ${clientIP}`);
        if (!wasAuthenticated && !isTrustedPeer) {
          const blocked = rateLimiter.recordFailure(clientIP);
          if (blocked) {
            console.log(`[RATE_LIMIT] IP ${clientIP} has been blocked`);
          }
        }
      }
    });

    aedes.handle(socket);
  });

  tcpServer.listen(TCP_PORT, HOST, () => {
    console.log(`TCP MQTT listening on:       mqtt://${HOST}:${TCP_PORT}`);
  });
}

// Start periodic $SYS telemetry publishing
sysMetrics.start();

httpServer.listen(WS_PORT, HOST, () => {
  const aedesVer = (aedes as any).version || '0.51.3';
  const bannerTitle = `MeshCore MQTT Broker v${brokerVersion}`.padEnd(51, ' ');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log(`║         ${bannerTitle}║`);
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log(`Runtime Environment:        Node.js ${process.version} (${process.platform}/${process.arch}, aedes v${aedesVer})`);
  if (peerIdentity) {
    console.log(`Broker Peer Public Key:     ${peerIdentity.publicKeyHex}`);
  }
  console.log(`WebSocket MQTT listening on: ws://${HOST}:${WS_PORT}`);
  if (ENABLE_TCP) {
    console.log(`Standard TCP MQTT listening on: mqtt://${HOST}:${TCP_PORT}`);
  } else {
    console.log('Standard TCP MQTT:          Disabled (ENABLE_TCP_MQTT=false)');
  }
  if (HTTP_REDIRECT_URL) {
    console.log(`HTTP Browser Redirect:      ${HTTP_REDIRECT_URL}`);
  } else {
    console.log('HTTP Browser Redirect:      Disabled (serving 200 OK status)');
  }
  console.log(`$SYS Telemetry Interval:    ${mqttConfig.sysIntervalMs}ms (Admin-only, retained)`);
  console.log(`Log Level:                  ${mqttConfig.logLevel}`);
  console.log('');
  console.log('Authentication Modes:');
  console.log(`  1. Subscribers (Subscribe-only): ${subscriberUsers.size} user(s) configured`);
  console.log('     Usernames:', Array.from(subscriberUsers.keys()).join(', '));
  console.log('');
  console.log('  2. Publishers (Publish-only):');
  console.log('     Username: v1_{PUBLIC_KEY}');
  console.log('     Password: JWT token signed with Ed25519 private key');
  console.log('     Validation:');
  console.log('       - origin_id must match authenticated public key');
  if (EXPECTED_AUDIENCE) {
    console.log(`       - Token audience must be: ${EXPECTED_AUDIENCE}`);
  }
  console.log('');
  console.log('  3. Peer Broker Interconnect (Origin-Only Forwarding):');
  if (peerIdentity) {
    console.log(`     Local Peer Public Key: ${peerIdentity.publicKeyHex}`);
  }
  console.log(`     Outbound Peers: ${peerConfig.peers.length}`);
  console.log(`     Authorized Inbound Peer Keys: ${peerConfig.authorizedPeerKeys?.size || 0}`);
  console.log('');
  console.log('Ready to accept connections...');
});

// Graceful shutdown
let isShuttingDown = false;
function shutdown(): void {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log('\n[SHUTDOWN] Closing MQTT broker...');
  sysMetrics.stop();
  if (peerBridgeManager) {
    peerBridgeManager.shutdown();
  }
  if (tcpServer) {
    tcpServer.close();
  }
  httpServer.close();
  rateLimiter.destroy();
  abuseDetector.shutdown();
  aedes.close(() => {
    console.log('[SHUTDOWN] Broker closed');
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
