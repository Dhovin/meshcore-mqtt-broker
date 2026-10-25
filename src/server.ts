import Aedes from 'aedes';
import { createServer } from 'http';
import { createServer as createTcpServer } from 'net';
import { WebSocketServer } from 'ws';
import { Duplex } from 'stream';
import { readFileSync } from 'fs';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { getAirportInfo } from 'airport-utils';
import { RateLimiter } from './rate-limiter.js';
import { getClientIP } from './ip-utils.js';
import { AbuseDetector } from './abuse-detector.js';
import { loadMqttConfig, loadAbuseConfig, loadSubscriberConfig } from './config.js';
import { timingSafeCompare } from './crypto-utils.js';
import { MqttStreamValidator } from './mqtt-packet-validator.js';
import { SysMetricsCollector, SubscriberAccountMeta } from './sys-metrics.js';

// Read broker version from package.json
let brokerVersion = '1.0.0';
try {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'));
  if (pkg.version) brokerVersion = pkg.version;
} catch {
  // Fallback to 1.0.0 if package.json cannot be read
}

// Load and validate configuration
const mqttConfig = loadMqttConfig();
const abuseConfig = loadAbuseConfig();
const subscriberConfig = loadSubscriberConfig();

const WS_PORT = mqttConfig.wsPort;
const TCP_PORT = mqttConfig.tcpPort;
const ENABLE_TCP = mqttConfig.enableTcp;
const HOST = mqttConfig.host;
const EXPECTED_AUDIENCE = mqttConfig.expectedAudience;
const HTTP_REDIRECT_URL = mqttConfig.httpRedirectUrl;

// Helper function to validate IATA airport codes
function isValidIATACode(code: string): boolean {
  try {
    getAirportInfo(code);
    return true;
  } catch {
    return false;
  }
}

// Client types
enum ClientType {
  SUBSCRIBER = 'subscriber',
  PUBLISHER = 'publisher'
}

// Subscriber roles
enum SubscriberRole {
  ADMIN = 1,           // Full access + can delete retained messages
  FULL_ACCESS = 2,     // Full access, no hidden data
  LIMITED = 3          // All access but with hidden/sensitive data filtered
}

// Load subscriber users from environment variables
// Format: SUBSCRIBER_1=username:password:role:maxConnections, SUBSCRIBER_2=username:password:role:maxConnections, etc.
// Role: 1=admin (full+delete), 2=full_access (no hidden data), 3=limited (filtered data)
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
      if (roleNum === 1 || roleNum === 2 || roleNum === 3) {
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
    
    const roleNames = {
      [SubscriberRole.ADMIN]: 'admin',
      [SubscriberRole.FULL_ACCESS]: 'full_access', 
      [SubscriberRole.LIMITED]: 'limited'
    };
    subscriberAccountsMeta.set(username, {
      roleName: roleNames[role],
      maxConnections: maxConn,
      activeConnections: activeSet,
    });
    console.log(`[CONFIG] Loaded subscriber user: ${username} (role: ${roleNames[role]}, maxConnections: ${maxConn})`);
  } else {
    console.warn(`[CONFIG] Invalid format for SUBSCRIBER_${subscriberIndex}: ${subscriberEnvVar}`);
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
  wsPort: WS_PORT,
  tcpEnabled: ENABLE_TCP,
  tcpPort: TCP_PORT,
  intervalMs: mqttConfig.sysIntervalMs,
});

// Helper to get client identifier for logging
function getClientLogPrefix(client: any): string {
  if (!client) return '[UNKNOWN]';
  
  const clientType = client.clientType;
  if (clientType === ClientType.PUBLISHER && client.publicKey) {
    return `[O:${client.publicKey.substring(0, 8)}]`;
  } else if (clientType === ClientType.SUBSCRIBER && client.username) {
    return `[S:${client.username}]`;
  }
  return `[C:${client.id}]`;
}

// Authentication handler
aedes.authenticate = async (client, username, password, callback) => {
  const logPrefix = `[C:${client.id}]`;
  console.log(`${logPrefix} [AUTH] Authentication attempt - Username: ${username}`);

  try {
    const usernameStr = username?.toString() || '';
    const passwordStr = password?.toString() || '';

    // Check if this is a subscriber login
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
        console.log(`${logPrefix} [AUTH] ✓ Subscriber authenticated (${usernameStr}, role: ${role}, connections: ${activeConns.size}/${maxConn})`);
        (client as any).clientType = ClientType.SUBSCRIBER;
        (client as any).username = usernameStr;
        (client as any).role = role;
        
        // Mark stream as authenticated
        const stream = (client as any).conn;
        if (stream && stream.clientIP) {
          stream.authenticated = true;
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

    // Otherwise, check for JWT-based publisher authentication
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
      console.log(`${logPrefix} [AUTH] Public key length: ${publicKey.length}, hex dump: ${Buffer.from(publicKey).toString('hex')}`);
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

    // Verify the auth token using meshcore-decoder
    const tokenPayload = await verifyAuthToken(passwordStr, publicKey);
    console.debug(`${logPrefix} [AUTH] Token input: "${passwordStr}"`);

    
    if (!tokenPayload) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid token signature`);
      console.debug(`${logPrefix} [AUTH] Token input: "${passwordStr}"`);      
      console.debug(`${logPrefix} [AUTH] Public key: ${publicKey}`);
      console.debug(`${logPrefix} [AUTH] Token hex: ${Buffer.from(passwordStr).toString('hex')}`);
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
    console.log(`[O:${shortKey}] [AUTH] ✓ Publisher authenticated${tokenPayload.aud ? ` [aud: ${tokenPayload.aud}]` : ''}`);
    // Store the public key and client type with the client for later use
    (client as any).publicKey = publicKey;
    (client as any).tokenPayload = tokenPayload;
    (client as any).clientType = ClientType.PUBLISHER;
    
    // Mark stream as authenticated
    const stream = (client as any).conn;
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
aedes.authorizePublish = (client, packet, callback) => {
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
    console.log(`${logPrefix} [AUTHZ] Stripping retain flag from STATUS message -> ${packet.topic}`);
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
    
    console.log(`${logPrefix} [AUTHZ] ✗ Publish denied (subscriber) -> ${packet.topic}`);
    sysMetrics.recordUnauthorizedPublish();
    callback(new Error('Subscriber clients are subscribe-only'));
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
    // Examples:
    //   meshcore/SEA/ABCD1234.../packets
    //   meshcore/SEA/ABCD1234.../status
    //   meshcore/SEA/ABCD1234.../internal (ADMIN only)
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
      console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('XXX is a placeholder - please configure your actual IATA location code'));
      client.close();
      return;
    }
    
    // Check if this is the special "test" region and normalize it to lowercase
    const isTestRegion = locationCode.toLowerCase() === 'test';
    
    if (isTestRegion) {
      console.log(`${logPrefix} [AUTHZ] ✓ Using test region -> ${packet.topic}`);
      // Continue to validation, don't return here
    } else {
      // First check format (must be 3 uppercase letters, no normalization)
      if (!iataRegex.test(locationCode)) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid format)`);
        console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid location format`);
        console.log(`${logPrefix} [DISCONNECT] Location code: "${locationCode}" (length: ${locationCode.length})`);
        console.log(`${logPrefix} [DISCONNECT] Location hex: ${Buffer.from(locationCode).toString('hex')}`);
        console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('Location must be exactly 3 uppercase letters (e.g., SEA, PDX, BOS) or "test"'));
        client.close();
        return;
      }
      
      // Then check if it's a valid IATA code
      if (!isValidIATACode(locationCode)) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid IATA)`);
        console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid IATA code`);
        console.log(`${logPrefix} [DISCONNECT] Location code: "${locationCode}"`);
        console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
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
      console.log(`${logPrefix} [DISCONNECT] Topic pubkey: "${topicPublicKey}" (length: ${topicPublicKey.length})`);
      console.log(`${logPrefix} [DISCONNECT] Topic pubkey hex: ${Buffer.from(topicPublicKey).toString('hex')}`);
      console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
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
      console.log(`${logPrefix} [DISCONNECT] Topic pubkey:  "${topicPublicKey}"`);
      console.log(`${logPrefix} [DISCONNECT] Client pubkey: "${clientPublicKey}"`);
      console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Public key in topic must match authenticated public key'));
      client.close();
      return;
    }

    // Normalize the topic to UPPERCASE for IATA codes and public key component
    // This prevents duplicate topics with different casing (e.g., 7553b337... vs 7553B337...)
    // For the test region, always normalize to lowercase "test"
    const normalizedLocation = isTestRegion ? 'test' : locationCode.toUpperCase();
    const normalizedTopic = `meshcore/${normalizedLocation}/${clientPublicKey}/${topicParts.slice(3).join('/')}`;
    (client as any).currentIata = normalizedLocation;
    
    // Update the packet topic to the normalized version
    if (packet.topic !== normalizedTopic) {
      console.log(`${logPrefix} [AUTHZ] Normalized topic: ${packet.topic} -> ${normalizedTopic}`);
      packet.topic = normalizedTopic;
    }

    // Special handling for serial/responses - payload is a JWT string, not JSON
    // Topic format: meshcore/{IATA}/{PUBLIC_KEY}/serial/responses
    const subtopic = topicParts.slice(3).join('/');

    // Protect /internal subtopic: only the broker may publish to /internal; direct client publishing is blocked
    if (subtopic === 'internal') {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (clients cannot publish to /internal directly)`);
      sysMetrics.recordUnauthorizedPublish();
      callback(new Error('Clients are not permitted to publish directly to /internal subtopics'));
      return;
    }
    if (subtopic === 'serial/responses') {
      const payload = packet.payload.toString('utf-8');
      // Validate it looks like a JWT (3 base64url parts separated by dots)
      const jwtParts = payload.split('.');
      if (jwtParts.length !== 3) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JWT format)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('serial/responses payload must be a valid JWT'));
        return;
      }
      // Basic JWT format check - each part should be base64url encoded
      const base64urlRegex = /^[A-Za-z0-9_-]+$/;
      if (!jwtParts.every(part => base64urlRegex.test(part))) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JWT encoding)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('serial/responses payload must be a valid JWT'));
        return;
      }
      console.log(`${logPrefix} [AUTHZ] ✓ Publish authorized (serial response) -> ${packet.topic}`);
      callback(null);
      return;
    }

    // Validate that the message contains origin_id matching the authenticated public key
    try {
      const payload = packet.payload.toString('utf-8');
      const message = JSON.parse(payload);
      
      if (!message.origin_id) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (missing origin_id)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('Message must contain origin_id field'));
        return;
      }
      
      // Normalize both to uppercase for comparison
      const messageOriginId = message.origin_id.toUpperCase();
      const normalizedClientKey = clientPublicKey.toUpperCase();
      
      if (messageOriginId !== normalizedClientKey) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (origin_id mismatch)`);
        sysMetrics.recordUnauthorizedPublish();
        callback(new Error('origin_id must match authenticated public key'));
        return;
      }
      
      // Track with abuse detector (no enforcement, just tracking)
      // Use normalizedLocation to ensure consistent tracking regardless of case
      
      // Check IATA changes
      const trustState = abuseDetector.getClientStats(clientPublicKey);
      if (trustState) {
        abuseDetector.checkIataChange(trustState, normalizedLocation);
        
        // Record packet
        abuseDetector.recordPacket(client, packet);
      }
      
      console.log(`${logPrefix} [AUTHZ] ✓ Publish authorized -> ${packet.topic}`);
      
      // Publish JWT payload to /internal topic (ADMIN-only, contains PII)
      const tokenPayload = (client as any).tokenPayload;
      if (tokenPayload) {
        // Use normalizedLocation to ensure consistent internal topic naming
        const internalTopic = `meshcore/${normalizedLocation}/${clientPublicKey}/internal`;
        
        // Build trust metrics for internal message
        let trustMetrics: any = null;
        
        if (trustState) {
          const clockQuality = trustState.clockTracking.erraticJumps.length === 0 ? 'stable' :
                             trustState.clockTracking.erraticJumps.length < 3 ? 'syncing' : 'erratic';
          
          trustMetrics = {
            status: trustState.status,
            enforcement_enabled: abuseConfig.enforcementEnabled,
            totalPacketsReceived: trustState.totalPacketsReceived,
            totalPacketsSilenced: trustState.totalPacketsSilenced,
            duplicateCount: trustState.duplicateCount,
            anomalyCount: trustState.anomalyCount,
            anomalies: trustState.anomalies.slice(0, 20).map(a => ({
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
              iataHistory: trustState.iataHistory.map(h => h.iata),
            },
            clockTracking: {
              estimatedOffset: trustState.clockTracking.estimatedOffset ? 
                Math.round(trustState.clockTracking.estimatedOffset / 1000) : undefined,
              erraticJumpCount: trustState.clockTracking.erraticJumps.length,
              lastDeviceTimestamp: trustState.clockTracking.lastDeviceTimestamp,
              clockQuality,
            },
            recentIPs: trustState.recentIPs.slice(0, 10).map(ip => ({
              ip: ip.ip,
              connectionCount: ip.connectionCount,
              lastSeen: ip.lastSeen,
            })),
          };
        }
        
        const internalMessage = {
          origin_id: clientPublicKey,
          timestamp: Date.now(),
          jwt_payload: tokenPayload,
          trust_state: trustMetrics,
        };
        
        // Publish to internal topic (retained so admins can see it later)
        aedes.publish({
          cmd: 'publish',
          topic: internalTopic,
          payload: Buffer.from(JSON.stringify(internalMessage)),
          qos: 0,
          dup: false,
          retain: true
        }, (err) => {
          if (err) {
            console.error(`${logPrefix} [INTERNAL] Failed to publish JWT payload:`, err);
          } else {
            console.log(`${logPrefix} [INTERNAL] Published JWT payload -> ${internalTopic}`);
          }
        });
      }
      
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
  
  const logPrefix = getClientLogPrefix(client);
  const clientType = (client as any).clientType;
  
  // Publisher clients cannot subscribe (publish-only) - EXCEPT their own serial/commands topic
  if (clientType === ClientType.PUBLISHER) {
    // Allow publishers to subscribe to their own serial/commands topic for remote serial access
    // Topic format: meshcore/{IATA}/{PUBLIC_KEY}/serial/commands
    if (subscription.topic.endsWith('/serial/commands')) {
      const parts = subscription.topic.split('/');
      if (parts.length === 5 && parts[0] === 'meshcore' && parts[3] === 'serial') {
        const topicPublicKey = parts[2].toUpperCase();
        const clientPublicKey = ((client as any).publicKey || '').toUpperCase();
        // Publisher can only subscribe to their OWN serial/commands topic
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

// Track last seen status timestamp per origin_id to prevent race conditions
const lastStatusTimestamps = new Map<string, number>();

// Authorization handler for forwarding messages to subscribers (filter sensitive data)
aedes.authorizeForward = (client, packet) => {
  if (!client) {
    return packet;
  }
  
  const clientType = (client as any).clientType;
  const role = (client as any).role;
  
  // Block $SYS/* messages for non-admin subscribers (only role 1 can see system topics)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.startsWith('$SYS/')) {
      return null; // Block delivery of this message
    }
  }
  
  // Critical: Block /internal topics for non-admin subscribers (contains PII)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.includes('/internal')) {
      return null; // Block delivery of this message
    }
  }
  
  // Block /serial/* topics for non-admin subscribers (remote serial access is admin-only)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.includes('/serial/')) {
      return null; // Block delivery of this message
    }
  }
  
  // Prevent stale status messages from overwriting newer ones (LWT race condition)
  if (packet.topic.endsWith('/status') && packet.payload && packet.payload.length > 0) {
    try {
      const message = JSON.parse(packet.payload.toString());
      const originId = message.origin_id;
      const timestamp = message.timestamp ? new Date(message.timestamp).getTime() : 0;
      
      if (originId && timestamp) {
        const lastTimestamp = lastStatusTimestamps.get(originId) || 0;
        
        if (timestamp < lastTimestamp) {
          // This is a stale status message (probably a delayed LWT)
          console.log(`[FILTER] Blocking stale status message for ${originId.substring(0, 8)} (${new Date(timestamp).toISOString()} < ${new Date(lastTimestamp).toISOString()})`);
          sysMetrics.recordStaleStatusFiltered();
          return null; // Block this stale message
        }
        
        // Update the last seen timestamp
        lastStatusTimestamps.set(originId, timestamp);
      }
    } catch (error) {
      // If parsing fails, let it through (don't block non-JSON status messages)
      console.debug(`[FILTER] Failed to parse status message for timestamp check:`, error);
    }
  }
  
  // Only filter for LIMITED role subscribers (role 3)
  if (clientType === ClientType.SUBSCRIBER && role === SubscriberRole.LIMITED) {
    // Filter status messages (meshcore/*/status) to remove stats, model, and firmware_version
    if (packet.topic.endsWith('/status') && packet.payload && packet.payload.length > 0) {
      try {
        const message = JSON.parse(packet.payload.toString());
        
        // Track if we need to filter anything
        let filtered = false;
        
        // Remove the stats object if it exists
        if (message.stats) {
          delete message.stats;
          filtered = true;
        }
        
        // Remove model if it exists
        if (message.model !== undefined) {
          delete message.model;
          filtered = true;
        }
        
        // Remove firmware_version if it exists
        if (message.firmware_version !== undefined) {
          delete message.firmware_version;
          filtered = true;
        }
        
        // Only create new packet if we actually filtered something
        if (filtered) {
          return {
            ...packet,
            payload: Buffer.from(JSON.stringify(message))
          };
        }
      } catch (error) {
        // If JSON parsing fails, just return the original packet
        console.debug(`[FILTER] Failed to parse status message for filtering:`, error);
      }
    }
    
    // Filter packet messages (meshcore/*/packets) to remove SNR, RSSI, score
    if (packet.topic.endsWith('/packets') && packet.payload && packet.payload.length > 0) {
      try {
        const message = JSON.parse(packet.payload.toString());
        
        // Remove radio metrics if they exist
        let filtered = false;
        if (message.SNR !== undefined) {
          delete message.SNR;
          filtered = true;
        }
        if (message.RSSI !== undefined) {
          delete message.RSSI;
          filtered = true;
        }
        if (message.score !== undefined) {
          delete message.score;
          filtered = true;
        }
        
        // Only create new packet if we actually filtered something
        if (filtered) {
          return {
            ...packet,
            payload: Buffer.from(JSON.stringify(message))
          };
        }
      } catch (error) {
        // If JSON parsing fails, just return the original packet
        console.debug(`[FILTER] Failed to parse packet message for filtering:`, error);
      }
    }
  }
  
  // No filtering needed - return original packet
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
  console.log(`${logPrefix} [CLIENT] Connected`);
  console.log(`${logPrefix} [CLIENT] Connection details - conn exists: ${!!(client as any).conn}, clientIP: ${(client as any).conn?.clientIP}`);
  
  // Track when this client connected for disconnect timing and $SYS metrics
  (client as any).connectedAt = Date.now();
  sysMetrics.recordClientConnected((aedes as any).connectedClients || 1);
  
  // Hook into the client's stream close event to see WHO closed it
  const stream = (client as any).stream;
  if (stream) {
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
  
  // Log additional info to debug why this client disconnected
  if (client) {
    console.log(`${logPrefix} [CLIENT] Disconnect details - clientType: ${(client as any).clientType}, publicKey: ${(client as any).publicKey?.substring(0, 8)}`);
    
    // Clean up subscriber connection tracking
    const clientType = (client as any).clientType;
    const username = (client as any).username;
    if (clientType === ClientType.SUBSCRIBER && username) {
      const activeConns = subscriberActiveConnections.get(username);
      if (activeConns) {
        activeConns.delete(client.id);
        const maxConn = subscriberMaxConnections.get(username) || subscriberConfig.defaultMaxConnections;
        console.log(`${logPrefix} [CLIENT] Subscriber connection removed (${username}, connections: ${activeConns.size}/${maxConn})`);
      }
    }
  }
});

aedes.on('publish', (packet, client) => {
  sysMetrics.recordPublish(packet.topic, packet.payload.length, Boolean(packet.retain), Boolean(client));
  if (client) {
    const logPrefix = getClientLogPrefix(client);
    console.log(`${logPrefix} [PUBLISH] ${packet.topic} (${packet.payload.length} bytes)`);
  } else if (!packet.topic.startsWith('$SYS/')) {
    console.log(`[PUBLISH] Internal -> ${packet.topic} (${packet.payload.length} bytes)`);
  }
});

aedes.on('subscribe', (subscriptions, client) => {
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [SUBSCRIBE] Attempting to subscribe to: ${subscriptions.map(s => s.topic).join(', ')}`);
});

// Log when client sends DISCONNECT packet (graceful disconnect)
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
      console.log(`[HTTP] Non-WebSocket request from ${clientIP}, redirecting to ${HTTP_REDIRECT_URL}`);
      res.writeHead(302, { 'Location': HTTP_REDIRECT_URL });
      res.end();
      return;
    }

    console.log(`[HTTP] Non-WebSocket status request from ${clientIP}`);
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
      // Terminate immediately without trying to send a close frame
      ws.terminate();
      return;
    }
    
    console.log(`[WEBSOCKET] New WebSocket connection from ${clientIP}`);
  
  // Enable WebSocket ping/pong to keep connection alive
  ws.on('ping', (data) => {
    console.log(`[WEBSOCKET] Received WebSocket PING from ${clientIP}, sending PONG`);
    ws.pong(data);
  });
  
  ws.on('pong', () => {
    console.log(`[WEBSOCKET] Received WebSocket PONG from ${clientIP}`);
  });
  
  // Handle WebSocket errors
  ws.on('error', (error) => {
    // Log other WebSocket errors
    console.error(`[WEBSOCKET] Error from ${clientIP}:`, error.message);
  });
  
  // Create per-connection MQTT packet validator with headroom for topic and header bytes
  const packetValidator = new MqttStreamValidator(mqttConfig.maxPacketBytes + 4096);

  // Create a duplex stream from the WebSocket
  const stream = new Duplex({
    read() {
      // Resume WebSocket reads when consumer is ready for more data
      if (ws.readyState === ws.OPEN) {
        ws.resume();
      }
    },
    write(chunk, encoding, callback) {
      if (ws.readyState === ws.OPEN) {
        // Log MQTT PINGRESP packets (0xD0 = PINGRESP)
        if (chunk instanceof Buffer && chunk.length >= 2 && chunk[0] === 0xD0) {
          const clientInfo = (stream as any).client;
          if (clientInfo) {
            const logPrefix = getClientLogPrefix(clientInfo);
            console.log(`${logPrefix} [MQTT] Sending PINGRESP (PONG) to client`);
          } else {
            console.log(`[MQTT] Sending PINGRESP (PONG) to unauthenticated client`);
          }
        }
        
        ws.send(chunk, (error) => {
          // Suppress EPIPE errors - they're expected when client disconnects
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

    // Validate MQTT packet size before buffering to prevent memory exhaustion
    const valErr = packetValidator.processChunk(buf);
    if (valErr) {
      const clientInfo = (stream as any).client;
      const logPrefix = clientInfo ? getClientLogPrefix(clientInfo) : '[C:unauth]';
      console.log(`${logPrefix} [MQTT] ✗ Connection dropped: ${valErr.message} from ${clientIP}`);
      ws.terminate();
      stream.destroy();
      return;
    }

    // Log MQTT PINGREQ packets (0xC0 = PINGREQ) with client identifier
    if (buf.length >= 2 && buf[0] === 0xC0) {
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
      // Pause incoming WebSocket reads when duplex buffer is full
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
    
    // Check if client properly authenticated (has clientType set)
    const hasValidAuth = clientInfo && (clientInfo as any).clientType;
    
    if (hasValidAuth) {
      const logPrefix = getClientLogPrefix(clientInfo);
      console.log(`${logPrefix} [WEBSOCKET] Connection closed from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
    } else {
      // Unauthenticated or invalid client - count as failed connection
      console.log(`[C:${clientInfo?.id || 'null'}] [WEBSOCKET] Connection closed (unauthenticated) from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
      
      if (!wasAuthenticated) {
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
    const clientInfo = (stream as any).client;
    if (clientInfo) {
      const logPrefix = getClientLogPrefix(clientInfo);
      console.log(`${logPrefix} [STREAM] Stream ended, closing WebSocket`);
    } else {
      console.log('[STREAM] Stream ended (unauthenticated), closing WebSocket');
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

    // Check if IP is blocked
    if (rateLimiter.isBlocked(clientIP)) {
      console.log(`[RATE_LIMIT] Rejecting TCP connection from blocked IP: ${clientIP}`);
      socket.destroy();
      return;
    }

    console.log(`[TCP] New TCP MQTT connection from ${clientIP}`);
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
      console.error(`[TCP] Error from ${clientIP}:`, error.message);
    });

    socket.on('close', () => {
      const clientInfo = (socket as any).client;
      const wasAuthenticated = (socket as any).authenticated;
      const hasValidAuth = clientInfo && (clientInfo as any).clientType;

      if (hasValidAuth) {
        const logPrefix = getClientLogPrefix(clientInfo);
        console.log(`${logPrefix} [TCP] Connection closed from ${clientIP}`);
      } else {
        console.log(`[C:${clientInfo?.id || 'null'}] [TCP] Connection closed (unauthenticated) from ${clientIP}`);
        if (!wasAuthenticated) {
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
  console.log('Ready to accept connections...');
});

// Graceful shutdown
let isShuttingDown = false;
function shutdown(): void {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log('\n[SHUTDOWN] Closing MQTT broker...');
  sysMetrics.stop();
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
