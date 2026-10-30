import type Aedes from 'aedes';
import { performance } from 'node:perf_hooks';
import type { RateLimiter } from './rate-limiter.js';
import type { AbuseDetector } from './abuse-detector.js';
import type { OutboundPeerStats } from './peer-bridge.js';

// 60 buckets of 5 seconds each = 300 seconds (5 minutes) rolling window
const BUCKET_DURATION_MS = 5000;
const RING_BUFFER_SIZE = 60;
const ONE_MINUTE_BUCKETS = 12; // 12 * 5s = 60s

export interface SubscriberAccountMeta {
  roleName: string;
  maxConnections: number;
  activeConnections: Set<string>;
}

export interface InboundPeerRecord {
  id: string;
  publicKey: string | null;
  username: string | null;
  authMode: 'ed25519_jwt' | 'role4_credentials';
  lastClientIp: string | null;
  lastConnectedAt: number | null;
  lastSeenAt: number;
  packetsReceived: number;
  bytesReceived: number;
  bySubtopic: {
    packets: number;
    status: number;
    neighbors: number;
    raw: number;
  };
  duplicatesFiltered: number;
  rateLimited: number;
  invalidDropped: number;
}

export interface SysMetricsOptions {
  aedes: Aedes;
  rateLimiter: RateLimiter;
  abuseDetector: AbuseDetector;
  subscriberAccounts: Map<string, SubscriberAccountMeta>;
  brokerVersion: string;
  brokerPublicKey?: string;
  authorizedPeerKeysCount?: number;
  wsPort: number;
  tcpEnabled: boolean;
  tcpPort: number;
  intervalMs?: number;
  getPeerStats?: () => Record<string, OutboundPeerStats>;
}

export class SysMetricsCollector {
  private readonly aedes: Aedes;
  private readonly rateLimiter: RateLimiter;
  private readonly abuseDetector: AbuseDetector;
  private readonly subscriberAccounts: Map<string, SubscriberAccountMeta>;
  private readonly versionString: string;
  private readonly brokerPublicKey?: string;
  private readonly authorizedPeerKeysCount: number;
  private readonly wsPort: number;
  private readonly tcpEnabled: boolean;
  private readonly tcpPort: number;
  private readonly intervalMs: number;
  private readonly startedAtMs: number;
  private readonly startedAtIso: string;
  private readonly getPeerStats?: SysMetricsOptions['getPeerStats'];

  private timer?: NodeJS.Timeout;
  private lastCpuUsage = process.cpuUsage();
  private lastCpuCheckTime = performance.now();
  private lastLoopCheckTime = performance.now();
  private eventLoopLagMs = 0;

  // Connection & auth counters
  private maximumClients = 0;
  private totalConnections = 0;
  private totalDisconnects = 0;
  private authFailures = 0;
  private unauthorizedPublishes = 0;
  private staleStatusFiltered = 0;
  private duplicatesFiltered = 0;
  private peerRateLimited = 0;

  // Inbound peer tracking
  private inboundPeerPacketsReceived = 0;
  private inboundPeerBytesReceived = 0;
  private inboundPeerDuplicatesFiltered = 0;
  private inboundPeerInvalidDropped = 0;
  private readonly inboundPeers = new Map<string, InboundPeerRecord>();

  // Traffic counters
  private totalMessagesReceived = 0;
  private totalBytesReceived = 0;
  private readonly subtopicCounts = {
    packets: 0,
    status: 0,
    serial_commands: 0,
    serial_responses: 0,
    internal: 0,
    other: 0,
  };

  // Fixed-size typed ring buffer for 1m and 5m rolling traffic rates (zero allocations on hot path)
  private readonly slotEpochs = new Float64Array(RING_BUFFER_SIZE);
  private readonly slotMessages = new Uint32Array(RING_BUFFER_SIZE);
  private readonly slotBytes = new Float64Array(RING_BUFFER_SIZE);

  // Track retained non-$SYS topics for O(1) retained message count
  private readonly retainedTopics = new Set<string>();
  // Track published IATA regions so stale regions can be cleaned up if evicted
  private readonly publishedRegions = new Set<string>();
  // Deduplicate retained $SYS publishes when scalar/JSON payloads have not changed
  private readonly lastPublishedPayloads = new Map<string, string>();

  constructor(options: SysMetricsOptions) {
    this.aedes = options.aedes;
    this.rateLimiter = options.rateLimiter;
    this.abuseDetector = options.abuseDetector;
    this.subscriberAccounts = options.subscriberAccounts;
    this.brokerPublicKey = options.brokerPublicKey;
    this.authorizedPeerKeysCount = options.authorizedPeerKeysCount ?? 0;
    this.wsPort = options.wsPort;
    this.tcpEnabled = options.tcpEnabled;
    this.tcpPort = options.tcpPort;
    this.intervalMs = options.intervalMs ?? 10000;
    this.getPeerStats = options.getPeerStats;
    this.startedAtMs = Date.now();
    this.startedAtIso = new Date(this.startedAtMs).toISOString();

    const aedesVersion = (this.aedes as any).version || '0.51.3';
    this.versionString = `meshcore-mqtt-broker v${options.brokerVersion} (aedes ${aedesVersion}, node ${process.version})`;
  }

  /**
   * Start periodic $SYS telemetry publishing and emit initial snapshot immediately
   */
  public start(): void {
    if (this.timer) return;

    this.publishSnapshot();

    this.timer = setInterval(() => {
      const nowPerf = performance.now();
      const expectedElapsed = this.intervalMs;
      const actualElapsed = nowPerf - this.lastLoopCheckTime;
      this.eventLoopLagMs = Math.max(0, Math.round((actualElapsed - expectedElapsed) * 100) / 100);
      this.lastLoopCheckTime = nowPerf;

      this.publishSnapshot();
    }, this.intervalMs);

    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  /**
   * Stop periodic $SYS telemetry publishing
   */
  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /**
   * Record a successful client authentication/connection
   */
  public recordClientConnected(currentConnectedCount: number): void {
    this.totalConnections++;
    if (currentConnectedCount > this.maximumClients) {
      this.maximumClients = currentConnectedCount;
    }
  }

  /**
   * Record a client disconnection
   */
  public recordClientDisconnected(): void {
    this.totalDisconnects++;
  }

  /**
   * Record a failed authentication attempt
   */
  public recordAuthFailure(): void {
    this.authFailures++;
  }

  /**
   * Record a denied publish attempt
   */
  public recordUnauthorizedPublish(): void {
    this.unauthorizedPublishes++;
  }

  /**
   * Record a dropped out-of-order / stale /status message
   */
  public recordStaleStatusFiltered(): void {
    this.staleStatusFiltered++;
  }

  /**
   * Record a dropped cross-path duplicate packet
   */
  public recordDuplicateFiltered(): void {
    this.duplicatesFiltered++;
  }

  /**
   * Record an inbound peer packet dropped due to PEER_RATE_LIMIT_PER_SEC
   */
  public recordPeerRateLimited(client?: any): void {
    this.peerRateLimited++;
    if (client) {
      const rec = this.getOrCreateInboundPeerRecord(client);
      rec.rateLimited++;
      rec.lastSeenAt = Date.now();
    }
  }

  /**
   * Record a valid inbound peer publish
   */
  public recordInboundPeerPublish(client: any, subtopic: string, payloadBytes: number): void {
    this.inboundPeerPacketsReceived++;
    this.inboundPeerBytesReceived += payloadBytes;
    const rec = this.getOrCreateInboundPeerRecord(client);
    rec.packetsReceived++;
    rec.bytesReceived += payloadBytes;
    rec.lastSeenAt = Date.now();
    if (subtopic === 'packets') rec.bySubtopic.packets++;
    else if (subtopic === 'status') rec.bySubtopic.status++;
    else if (subtopic === 'neighbors') rec.bySubtopic.neighbors++;
    else if (subtopic === 'raw') rec.bySubtopic.raw++;
  }

  /**
   * Record an inbound peer packet dropped as a cross-path duplicate
   */
  public recordInboundPeerDuplicate(client: any): void {
    this.inboundPeerDuplicatesFiltered++;
    const rec = this.getOrCreateInboundPeerRecord(client);
    rec.duplicatesFiltered++;
    rec.lastSeenAt = Date.now();
  }

  /**
   * Record an invalid/unauthorized packet from an inbound peer
   */
  public recordInboundPeerInvalid(client: any): void {
    this.inboundPeerInvalidDropped++;
    const rec = this.getOrCreateInboundPeerRecord(client);
    rec.invalidDropped++;
    rec.lastSeenAt = Date.now();
  }

  private getOrCreateInboundPeerRecord(client: any): InboundPeerRecord {
    const pubKey: string | undefined = client?.publicKey;
    const username: string | undefined = client?.username;
    const id = pubKey ? pubKey.substring(0, 8) : username || client?.id || 'unknown';
    let rec = this.inboundPeers.get(id);
    if (!rec) {
      if (this.inboundPeers.size >= 500) {
        const oldestKey = this.inboundPeers.keys().next().value;
        if (oldestKey) this.inboundPeers.delete(oldestKey);
      }
      rec = {
        id,
        publicKey: pubKey ?? null,
        username: username ?? null,
        authMode: pubKey ? 'ed25519_jwt' : 'role4_credentials',
        lastClientIp: client?.conn?.clientIP ?? null,
        lastConnectedAt: client?.connectedAt ?? Date.now(),
        lastSeenAt: Date.now(),
        packetsReceived: 0,
        bytesReceived: 0,
        bySubtopic: { packets: 0, status: 0, neighbors: 0, raw: 0 },
        duplicatesFiltered: 0,
        rateLimited: 0,
        invalidDropped: 0,
      };
      this.inboundPeers.set(id, rec);
    } else {
      if (client?.conn?.clientIP) rec.lastClientIp = client.conn.clientIP;
      if (client?.connectedAt) rec.lastConnectedAt = client.connectedAt;
    }
    return rec;
  }

  /**
   * Record a published packet on the broker (hot path - O(1), zero allocations)
   */
  public recordPublish(topic: string, payloadLength: number, retain: boolean, isClientPublish: boolean): void {
    // Do not count $SYS internal publishes in retainedTopics or traffic throughput
    if (topic.startsWith('$SYS/')) {
      if (retain && payloadLength === 0) {
        this.lastPublishedPayloads.delete(topic);
      }
      return;
    }

    // Track non-$SYS retained message set
    if (retain) {
      if (payloadLength === 0) {
        this.retainedTopics.delete(topic);
      } else {
        this.retainedTopics.add(topic);
      }
    }

    if (topic.endsWith('/internal')) {
      this.subtopicCounts.internal++;
      return;
    }

    if (!isClientPublish) {
      return;
    }

    this.totalMessagesReceived++;
    this.totalBytesReceived += payloadLength;

    // Classify subtopic without allocating arrays
    if (topic.endsWith('/packets')) {
      this.subtopicCounts.packets++;
    } else if (topic.endsWith('/status')) {
      this.subtopicCounts.status++;
    } else if (topic.endsWith('/serial/commands')) {
      this.subtopicCounts.serial_commands++;
    } else if (topic.endsWith('/serial/responses')) {
      this.subtopicCounts.serial_responses++;
    } else {
      this.subtopicCounts.other++;
    }

    // Update fixed ring buffer slot
    const epoch = Math.floor(Date.now() / BUCKET_DURATION_MS);
    const slot = epoch % RING_BUFFER_SIZE;
    if (this.slotEpochs[slot] !== epoch) {
      this.slotEpochs[slot] = epoch;
      this.slotMessages[slot] = 1;
      this.slotBytes[slot] = payloadLength;
    } else {
      this.slotMessages[slot] += 1;
      this.slotBytes[slot] += payloadLength;
    }
  }

  /**
   * Format uptime seconds into a human-readable string (e.g. "2d 4h 15m 10s")
   */
  public static formatUptime(totalSeconds: number): string {
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (days > 0) return `${days}d ${hours}h ${minutes}m ${seconds}s`;
    if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  }

  /**
   * Compute rolling 1-minute and 5-minute message/byte rates from the ring buffer
   */
  private computeRollingRates(nowMs: number, uptimeSeconds: number) {
    const currentEpoch = Math.floor(nowMs / BUCKET_DURATION_MS);
    let msgs1m = 0;
    let bytes1m = 0;
    let msgs5m = 0;
    let bytes5m = 0;

    for (let i = 0; i < RING_BUFFER_SIZE; i++) {
      const ageEpochs = currentEpoch - this.slotEpochs[i];
      if (ageEpochs >= 0 && ageEpochs < RING_BUFFER_SIZE) {
        const m = this.slotMessages[i];
        const b = this.slotBytes[i];
        msgs5m += m;
        bytes5m += b;
        if (ageEpochs < ONE_MINUTE_BUCKETS) {
          msgs1m += m;
          bytes1m += b;
        }
      }
    }

    const window1mSec = Math.max(1, Math.min(uptimeSeconds, 60));
    const window5mSec = Math.max(1, Math.min(uptimeSeconds, 300));

    return {
      messagesPerSec1m: Math.round((msgs1m / window1mSec) * 100) / 100,
      messagesPerSec5m: Math.round((msgs5m / window5mSec) * 100) / 100,
      bytesPerSec1m: Math.round((bytes1m / window1mSec) * 100) / 100,
      bytesPerSec5m: Math.round((bytes5m / window5mSec) * 100) / 100,
    };
  }

  /**
   * Collect all broker metrics in a single pass and publish retained $SYS/broker/# topics
   */
  public publishSnapshot(): void {
    if (this.aedes.closed) return;

    const nowMs = Date.now();
    const uptimeSeconds = Math.max(0, Math.floor((nowMs - this.startedAtMs) / 1000));
    const uptimeFormatted = SysMetricsCollector.formatUptime(uptimeSeconds);

    // 1. System / process health
    const mem = process.memoryUsage();
    const rssMb = Math.round((mem.rss / 1048576) * 100) / 100;
    const heapUsedMb = Math.round((mem.heapUsed / 1048576) * 100) / 100;
    const heapTotalMb = Math.round((mem.heapTotal / 1048576) * 100) / 100;
    const externalMb = Math.round((mem.external / 1048576) * 100) / 100;

    const nowPerf = performance.now();
    const elapsedUs = Math.max(1, (nowPerf - this.lastCpuCheckTime) * 1000);
    const cpuDelta = process.cpuUsage(this.lastCpuUsage);
    this.lastCpuUsage = process.cpuUsage();
    this.lastCpuCheckTime = nowPerf;
    const cpuPercent = Math.round(((cpuDelta.user + cpuDelta.system) / elapsedUs) * 10000) / 100;

    // 2. Single-pass inspection of connected Aedes clients
    const clientsMap = (this.aedes as any).clients || {};
    let connectedClients = 0;
    let connectedPublishers = 0;
    let connectedSubscribers = 0;
    let connectedPeers = 0;
    let adminSubscribers = 0;
    let fullAccessSubscribers = 0;
    let limitedSubscribers = 0;
    let wsConnections = 0;
    let tcpConnections = 0;
    let activeSubscriptions = 0;

    const connectedByIata: Record<string, string[]> = {};
    const connectedInboundPeers = new Map<string, any>();

    for (const clientId of Object.keys(clientsMap)) {
      const client = clientsMap[clientId];
      if (!client || client.closed) continue;

      connectedClients++;

      const transport = client.conn?.transport;
      if (transport === 'tcp') {
        tcpConnections++;
      } else {
        wsConnections++;
      }

      if (client.subscriptions) {
        for (const subTopic of Object.keys(client.subscriptions)) {
          // Exclude Aedes internal wildcard/dollar sign wrappers from inflation if any
          if (subTopic) activeSubscriptions++;
        }
      }

      if (client.clientType === 'publisher') {
        connectedPublishers++;
        const pubKey: string | undefined = client.publicKey;
        const iata: string | undefined =
          client.currentIata ||
          (pubKey ? this.abuseDetector.getClientStats(pubKey)?.currentIata : undefined);
        if (iata) {
          let list = connectedByIata[iata];
          if (!list) {
            list = [];
            connectedByIata[iata] = list;
          }
          if (pubKey && list.length < 50) {
            list.push(pubKey.substring(0, 8));
          }
        }
      } else if (client.clientType === 'subscriber') {
        connectedSubscribers++;
        if (client.role === 1) adminSubscribers++;
        else if (client.role === 2) fullAccessSubscribers++;
        else limitedSubscribers++;
      } else if (client.clientType === 'peer') {
        connectedPeers++;
        const rec = this.getOrCreateInboundPeerRecord(client);
        connectedInboundPeers.set(rec.id, client);
      }
    }

    if (connectedClients > this.maximumClients) {
      this.maximumClients = connectedClients;
    }

    const subscribersByAccount: Record<string, { role: string; active: number; max: number }> = {};
    for (const [username, meta] of this.subscriberAccounts.entries()) {
      subscribersByAccount[username] = {
        role: meta.roleName,
        active: meta.activeConnections.size,
        max: meta.maxConnections,
      };
    }

    // 3. Abuse detector & regional summary (single-pass in AbuseDetector)
    const abuseSummary = this.abuseDetector.getAllStats();
    const rateLimiterStats = this.rateLimiter.getStats();
    const outboundPeerStats = this.getPeerStats ? this.getPeerStats() : {};

    // Merge connected publishers per IATA with 1h/tracked stats from AbuseDetector
    const allIatas = new Set<string>([
      ...Object.keys(connectedByIata),
      ...Object.keys(abuseSummary.activeByIata1h),
    ]);

    const regionsData: Record<string, {
      connectedPublishers: number;
      activePublishers1h: number;
      trackedPublishers: number;
      totalPacketsReceived: number;
      connectedPublisherPrefixes: string[];
    }> = {};

    let activeRegionCount = 0;
    for (const iata of Array.from(allIatas).sort()) {
      const connList = connectedByIata[iata] || [];
      const abuseRegion = abuseSummary.activeByIata1h[iata];
      const connectedCount = connList.length;
      const active1h = abuseRegion?.activePublishers1h ?? 0;

      if (connectedCount > 0 || active1h > 0) {
        activeRegionCount++;
      }

      regionsData[iata] = {
        connectedPublishers: connectedCount,
        activePublishers1h: active1h,
        trackedPublishers: abuseRegion?.trackedPublishers ?? connectedCount,
        totalPacketsReceived: abuseRegion?.totalPacketsReceived ?? 0,
        connectedPublisherPrefixes: connList,
      };
    }

    // 4. Rolling traffic rates
    const rates = this.computeRollingRates(nowMs, uptimeSeconds);

    // Build structured category JSON objects
    const systemJson = {
      timestamp: nowMs,
      version: this.versionString,
      publicKey: this.brokerPublicKey ?? null,
      startedAt: this.startedAtIso,
      uptimeSeconds,
      uptimeFormatted,
      listeners: {
        wsPort: this.wsPort,
        tcpEnabled: this.tcpEnabled,
        tcpPort: this.tcpEnabled ? this.tcpPort : null,
      },
      memory: {
        rssMb,
        heapUsedMb,
        heapTotalMb,
        externalMb,
      },
      cpuPercent,
      eventLoopLagMs: this.eventLoopLagMs,
      retainedMessages: this.retainedTopics.size,
      activeSubscriptions,
    };

    const clientsJson = {
      timestamp: nowMs,
      connected: connectedClients,
      maximum: this.maximumClients,
      totalConnections: this.totalConnections,
      totalDisconnects: this.totalDisconnects,
      publishers: connectedPublishers,
      peers: connectedPeers,
      subscribers: {
        total: connectedSubscribers,
        byRole: {
          admin: adminSubscribers,
          full_access: fullAccessSubscribers,
          limited: limitedSubscribers,
        },
        byAccount: subscribersByAccount,
      },
      byTransport: {
        websocket: wsConnections,
        tcp: tcpConnections,
      },
    };

    const trafficJson = {
      timestamp: nowMs,
      messages: {
        received: this.totalMessagesReceived,
        bytesReceived: this.totalBytesReceived,
      },
      rate: rates,
      bySubtopic: { ...this.subtopicCounts },
      staleStatusFiltered: this.staleStatusFiltered,
      duplicatesFiltered: this.duplicatesFiltered,
      peerRateLimited: this.peerRateLimited,
    };

    const securityJson = {
      timestamp: nowMs,
      authFailures: this.authFailures,
      unauthorizedPublishes: this.unauthorizedPublishes,
      rateLimiter: rateLimiterStats,
      abuseDetector: {
        enforcementEnabled: abuseSummary.enforcementEnabled,
        muteDurationSeconds: abuseSummary.muteDurationSeconds,
        trackedPublishers: abuseSummary.trackedPublishers,
        mutedPublishersCount: abuseSummary.mutedPublishersCount,
        wouldMutePublishersCount: abuseSummary.wouldMutePublishersCount,
        anomalousPublishersCount: abuseSummary.anomalousPublishersCount,
        totalPacketsReceived: abuseSummary.totalPacketsReceived,
        totalPacketsSilenced: abuseSummary.totalPacketsSilenced,
        totalDuplicates: abuseSummary.totalDuplicates,
        totalAnomalies: abuseSummary.totalAnomalies,
        violators: abuseSummary.violators,
        flaggedPublishers: abuseSummary.flaggedPublishers,
      },
    };

    // Aggregate outbound and inbound peer stats
    let outboundConnectedCount = 0;
    let outboundTotalForwarded = 0;
    let outboundTotalBytesForwarded = 0;
    let outboundTotalQueued = 0;
    let outboundTotalQueuedBytes = 0;
    let outboundTotalDropped = 0;
    let outboundTotalCoalescedStatus = 0;

    for (const p of Object.values(outboundPeerStats)) {
      if (p.connected) outboundConnectedCount++;
      outboundTotalForwarded += p.forwarded || 0;
      outboundTotalBytesForwarded += p.forwardedBytes || 0;
      outboundTotalQueued += p.queued || 0;
      outboundTotalQueuedBytes += p.queuedBytes || 0;
      outboundTotalDropped += p.dropped || 0;
      outboundTotalCoalescedStatus += p.coalescedStatus || 0;
    }

    const inboundPeersSnapshot: Record<string, any> = {};
    for (const [peerId, rec] of this.inboundPeers.entries()) {
      const liveClient = connectedInboundPeers.get(peerId);
      const isConnected = Boolean(liveClient);
      const connAt = liveClient?.connectedAt ?? rec.lastConnectedAt;
      inboundPeersSnapshot[peerId] = {
        id: rec.id,
        publicKey: rec.publicKey,
        username: rec.username,
        authMode: rec.authMode,
        connected: isConnected,
        clientIp: liveClient?.conn?.clientIP ?? rec.lastClientIp,
        connectedSince: isConnected && connAt ? new Date(connAt).toISOString() : null,
        uptimeSeconds: isConnected && connAt ? Math.max(0, Math.floor((nowMs - connAt) / 1000)) : 0,
        lastSeenAt: new Date(rec.lastSeenAt).toISOString(),
        packetsReceived: rec.packetsReceived,
        bytesReceived: rec.bytesReceived,
        bySubtopic: { ...rec.bySubtopic },
        duplicatesFiltered: rec.duplicatesFiltered,
        rateLimited: rec.rateLimited,
        invalidDropped: rec.invalidDropped,
      };
    }

    const peersJson = {
      timestamp: nowMs,
      publicKey: this.brokerPublicKey ?? null,
      authorizedPeerKeysCount: this.authorizedPeerKeysCount,
      inboundConnectedPeers: connectedPeers,
      inboundRateLimited: this.peerRateLimited,
      inbound: {
        connectedCount: connectedPeers,
        authorizedKeysCount: this.authorizedPeerKeysCount,
        totalPacketsReceived: this.inboundPeerPacketsReceived,
        totalBytesReceived: this.inboundPeerBytesReceived,
        duplicatesFiltered: this.inboundPeerDuplicatesFiltered,
        rateLimited: this.peerRateLimited,
        invalidDropped: this.inboundPeerInvalidDropped,
        peers: inboundPeersSnapshot,
      },
      outboundConnectedPeers: outboundConnectedCount,
      outboundPeersCount: Object.keys(outboundPeerStats).length,
      outboundTotals: {
        connectedCount: outboundConnectedCount,
        configuredCount: Object.keys(outboundPeerStats).length,
        totalForwarded: outboundTotalForwarded,
        totalBytesForwarded: outboundTotalBytesForwarded,
        totalQueued: outboundTotalQueued,
        totalQueuedBytes: outboundTotalQueuedBytes,
        totalDropped: outboundTotalDropped,
        totalCoalescedStatus: outboundTotalCoalescedStatus,
      },
      outbound: outboundPeerStats,
    };

    const regionsJson = {
      timestamp: nowMs,
      activeRegionCount,
      totalTrackedRegions: allIatas.size,
      regions: regionsData,
    };

    const summaryJson = {
      timestamp: nowMs,
      version: this.versionString,
      publicKey: this.brokerPublicKey ?? null,
      uptimeSeconds,
      uptimeFormatted,
      clients: {
        connected: connectedClients,
        maximum: this.maximumClients,
        publishers: connectedPublishers,
        peers: connectedPeers,
        subscribers: connectedSubscribers,
        websocket: wsConnections,
        tcp: tcpConnections,
      },
      regions: {
        activeRegionCount,
        connectedByRegion: Object.fromEntries(
          Object.entries(regionsData)
            .filter(([, r]) => r.connectedPublishers > 0 || r.activePublishers1h > 0)
            .map(([iata, r]) => [iata, r.connectedPublishers])
        ),
      },
      traffic: {
        messagesReceived: this.totalMessagesReceived,
        bytesReceived: this.totalBytesReceived,
        messagesPerSec1m: rates.messagesPerSec1m,
        bytesPerSec1m: rates.bytesPerSec1m,
        duplicatesFiltered: this.duplicatesFiltered,
        peerRateLimited: this.peerRateLimited,
      },
      security: {
        authFailures: this.authFailures,
        blockedIPs: rateLimiterStats.blockedIPCount,
        mutedPublishers: abuseSummary.mutedPublishersCount,
        wouldMutePublishers: abuseSummary.wouldMutePublishersCount,
        violatorsCount: abuseSummary.violators.length,
        totalAnomalies: abuseSummary.totalAnomalies,
      },
      system: {
        rssMb,
        heapUsedMb,
        cpuPercent,
        eventLoopLagMs: this.eventLoopLagMs,
        retainedMessages: this.retainedTopics.size,
      },
    };

    // Publish top-level & category JSON topics
    this.publishRetained('$SYS/broker/summary', JSON.stringify(summaryJson));
    this.publishRetained('$SYS/broker/version', this.versionString);
    if (this.brokerPublicKey) {
      this.publishRetained('$SYS/broker/public_key', this.brokerPublicKey);
    }
    this.publishRetained('$SYS/broker/started_at', this.startedAtIso);
    this.publishRetained('$SYS/broker/uptime', String(uptimeSeconds));
    this.publishRetained('$SYS/broker/uptime/formatted', uptimeFormatted);

    // System health topics
    this.publishRetained('$SYS/broker/system', JSON.stringify(systemJson));
    this.publishRetained('$SYS/broker/system/memory/rss_mb', String(rssMb));
    this.publishRetained('$SYS/broker/system/memory/heap_used_mb', String(heapUsedMb));
    this.publishRetained('$SYS/broker/system/memory/heap_total_mb', String(heapTotalMb));
    this.publishRetained('$SYS/broker/system/cpu_percent', String(cpuPercent));
    this.publishRetained('$SYS/broker/system/event_loop_lag_ms', String(this.eventLoopLagMs));
    this.publishRetained('$SYS/broker/system/retained_messages', String(this.retainedTopics.size));
    this.publishRetained('$SYS/broker/system/subscriptions', String(activeSubscriptions));

    // Clients topics
    this.publishRetained('$SYS/broker/clients', JSON.stringify(clientsJson));
    this.publishRetained('$SYS/broker/clients/connected', String(connectedClients));
    this.publishRetained('$SYS/broker/clients/maximum', String(this.maximumClients));
    this.publishRetained('$SYS/broker/clients/publishers', String(connectedPublishers));
    this.publishRetained('$SYS/broker/clients/peers', String(connectedPeers));
    this.publishRetained('$SYS/broker/clients/subscribers', String(connectedSubscribers));
    this.publishRetained('$SYS/broker/clients/websocket', String(wsConnections));
    this.publishRetained('$SYS/broker/clients/tcp', String(tcpConnections));
    this.publishRetained('$SYS/broker/clients/total_connections', String(this.totalConnections));
    this.publishRetained('$SYS/broker/clients/total_disconnects', String(this.totalDisconnects));
    this.publishRetained('$SYS/broker/clients/subscribers_by_account', JSON.stringify(subscribersByAccount));

    // Peers topics
    this.publishRetained('$SYS/broker/peers', JSON.stringify(peersJson));
    if (this.brokerPublicKey) {
      this.publishRetained('$SYS/broker/peers/public_key', this.brokerPublicKey);
    }
    this.publishRetained('$SYS/broker/peers/authorized_keys_count', String(this.authorizedPeerKeysCount));
    this.publishRetained('$SYS/broker/peers/inbound_connected', String(connectedPeers));
    this.publishRetained('$SYS/broker/peers/inbound/received_packets', String(this.inboundPeerPacketsReceived));
    this.publishRetained('$SYS/broker/peers/inbound/received_bytes', String(this.inboundPeerBytesReceived));
    this.publishRetained('$SYS/broker/peers/inbound/duplicates_filtered', String(this.inboundPeerDuplicatesFiltered));
    this.publishRetained('$SYS/broker/peers/inbound/rate_limited', String(this.peerRateLimited));
    this.publishRetained('$SYS/broker/peers/inbound/invalid_dropped', String(this.inboundPeerInvalidDropped));

    for (const [peerId, peerData] of Object.entries(inboundPeersSnapshot)) {
      this.publishRetained(`$SYS/broker/peers/inbound/${peerId}`, JSON.stringify(peerData));
      this.publishRetained(`$SYS/broker/peers/inbound/${peerId}/connected`, String(peerData.connected));
      this.publishRetained(`$SYS/broker/peers/inbound/${peerId}/received`, String(peerData.packetsReceived));
      this.publishRetained(`$SYS/broker/peers/inbound/${peerId}/received_bytes`, String(peerData.bytesReceived));
      this.publishRetained(`$SYS/broker/peers/inbound/${peerId}/duplicates_filtered`, String(peerData.duplicatesFiltered));
      this.publishRetained(`$SYS/broker/peers/inbound/${peerId}/rate_limited`, String(peerData.rateLimited));
    }

    this.publishRetained('$SYS/broker/peers/outbound_connected', String(outboundConnectedCount));
    this.publishRetained('$SYS/broker/peers/outbound_count', String(Object.keys(outboundPeerStats).length));
    this.publishRetained('$SYS/broker/peers/outbound/forwarded_packets', String(outboundTotalForwarded));
    this.publishRetained('$SYS/broker/peers/outbound/forwarded_bytes', String(outboundTotalBytesForwarded));
    this.publishRetained('$SYS/broker/peers/outbound/queued_packets', String(outboundTotalQueued));
    this.publishRetained('$SYS/broker/peers/outbound/queued_bytes', String(outboundTotalQueuedBytes));
    this.publishRetained('$SYS/broker/peers/outbound/dropped_packets', String(outboundTotalDropped));

    for (const [peerId, peerData] of Object.entries(outboundPeerStats)) {
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}`, JSON.stringify(peerData));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/connected`, String(peerData.connected));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/url`, peerData.url);
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/forwarded`, String(peerData.forwarded));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/forwarded_bytes`, String(peerData.forwardedBytes));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/queued`, String(peerData.queued));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/queued_bytes`, String(peerData.queuedBytes));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/dropped`, String(peerData.dropped));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/reconnect_attempts`, String(peerData.reconnectAttempts));
      this.publishRetained(`$SYS/broker/peers/outbound/${peerId}/uptime`, String(peerData.uptimeSeconds));
    }

    // Regional topics
    this.publishRetained('$SYS/broker/regions', JSON.stringify(regionsJson));
    this.publishRetained('$SYS/broker/regions/active_count', String(activeRegionCount));

    for (const [iata, data] of Object.entries(regionsData)) {
      this.publishedRegions.add(iata);
      this.publishRetained(`$SYS/broker/regions/${iata}`, JSON.stringify(data));
      this.publishRetained(`$SYS/broker/regions/${iata}/publishers`, String(data.connectedPublishers));
      this.publishRetained(`$SYS/broker/regions/${iata}/packets`, String(data.totalPacketsReceived));
    }

    // Clean up any previously published region that was evicted from retention
    for (const oldIata of this.publishedRegions) {
      if (!regionsData[oldIata]) {
        this.publishedRegions.delete(oldIata);
        this.publishRetained(`$SYS/broker/regions/${oldIata}`, '');
        this.publishRetained(`$SYS/broker/regions/${oldIata}/publishers`, '');
        this.publishRetained(`$SYS/broker/regions/${oldIata}/packets`, '');
      }
    }

    // Traffic topics
    this.publishRetained('$SYS/broker/traffic', JSON.stringify(trafficJson));
    this.publishRetained('$SYS/broker/traffic/messages/received', String(this.totalMessagesReceived));
    this.publishRetained('$SYS/broker/traffic/messages/bytes_received', String(this.totalBytesReceived));
    this.publishRetained('$SYS/broker/traffic/rate/messages_per_sec_1m', String(rates.messagesPerSec1m));
    this.publishRetained('$SYS/broker/traffic/rate/messages_per_sec_5m', String(rates.messagesPerSec5m));
    this.publishRetained('$SYS/broker/traffic/rate/bytes_per_sec_1m', String(rates.bytesPerSec1m));
    this.publishRetained('$SYS/broker/traffic/rate/bytes_per_sec_5m', String(rates.bytesPerSec5m));
    this.publishRetained('$SYS/broker/traffic/by_subtopic/packets', String(this.subtopicCounts.packets));
    this.publishRetained('$SYS/broker/traffic/by_subtopic/status', String(this.subtopicCounts.status));
    this.publishRetained('$SYS/broker/traffic/by_subtopic/serial_commands', String(this.subtopicCounts.serial_commands));
    this.publishRetained('$SYS/broker/traffic/by_subtopic/serial_responses', String(this.subtopicCounts.serial_responses));
    this.publishRetained('$SYS/broker/traffic/by_subtopic/internal', String(this.subtopicCounts.internal));
    this.publishRetained('$SYS/broker/traffic/stale_status_filtered', String(this.staleStatusFiltered));
    this.publishRetained('$SYS/broker/traffic/duplicates_filtered', String(this.duplicatesFiltered));
    this.publishRetained('$SYS/broker/traffic/peer_rate_limited', String(this.peerRateLimited));

    // Security topics
    this.publishRetained('$SYS/broker/security', JSON.stringify(securityJson));
    this.publishRetained('$SYS/broker/security/auth_failures', String(this.authFailures));
    this.publishRetained('$SYS/broker/security/unauthorized_publishes', String(this.unauthorizedPublishes));
    this.publishRetained('$SYS/broker/security/rate_limiter', JSON.stringify(rateLimiterStats));
    this.publishRetained('$SYS/broker/security/rate_limiter/blocked_ips_count', String(rateLimiterStats.blockedIPCount));
    this.publishRetained('$SYS/broker/security/rate_limiter/tracked_ips_count', String(rateLimiterStats.trackedIPCount));
    this.publishRetained('$SYS/broker/security/rate_limiter/total_blocked_attempts', String(rateLimiterStats.totalBlockedAttempts));
    this.publishRetained('$SYS/broker/security/abuse_detector', JSON.stringify(securityJson.abuseDetector));
    this.publishRetained('$SYS/broker/security/abuse_detector/violators', JSON.stringify(abuseSummary.violators));
    this.publishRetained('$SYS/broker/security/abuse_detector/muted_count', String(abuseSummary.mutedPublishersCount));
    this.publishRetained('$SYS/broker/security/abuse_detector/would_mute_count', String(abuseSummary.wouldMutePublishersCount));
    this.publishRetained('$SYS/broker/security/abuse_detector/anomalies_total', String(abuseSummary.totalAnomalies));
    this.publishRetained('$SYS/broker/security/abuse_detector/duplicates_total', String(abuseSummary.totalDuplicates));
    this.publishRetained('$SYS/broker/security/abuse_detector/silenced_total', String(abuseSummary.totalPacketsSilenced));
  }

  /**
   * Publish a retained $SYS topic only if its payload has changed since the last tick
   */
  private publishRetained(topic: string, payloadStr: string): void {
    const previous = this.lastPublishedPayloads.get(topic);
    if (previous === payloadStr) {
      return;
    }

    if (payloadStr.length === 0) {
      this.lastPublishedPayloads.delete(topic);
    } else {
      this.lastPublishedPayloads.set(topic, payloadStr);
    }

    this.aedes.publish(
      {
        cmd: 'publish',
        topic,
        payload: Buffer.from(payloadStr, 'utf-8'),
        qos: 0,
        dup: false,
        retain: true,
      },
      () => {}
    );
  }
}
