import { createHash } from 'crypto';
import { DatabaseSync } from 'node:sqlite';

// Cap the per-client anomaly log. Without a bound, chronically noisy clients
// accumulate multi-MB logs that the synchronous 5-minute save cycle must
// JSON.stringify, stalling the event loop long enough to flap subscriber
// keepalives. anomalyCount (a counter) still tracks the lifetime total.
const MAX_STORED_ANOMALIES = 100;

// Peak-rate decay window (1 hour)
const RATE_WINDOW_MS = 3600000;
// 10 one-second buckets for O(1) rolling 10-second packet rate calculation
const RECENT_RATE_BUCKETS = 10;
// Default 4-hour temporary mute timeout (4 * 60 * 60 * 1000 ms)
const DEFAULT_MUTE_DURATION_MS = 14400000;

// ============================================================================
// Type Definitions
// ============================================================================

export interface ClientTrustState {
  // Identity
  publicKey: string;
  username: string;
  connectedAt: number;
  
  // Network tracking
  recentIPs: {
    ip: string;
    firstSeen: number;
    lastSeen: number;
    connectionCount: number;
  }[];
  
  // Status & temporary timeout tracking
  status: 'allowed' | 'muted' | 'would_mute';
  mutedAt?: number;
  mutedUntil?: number;
  muteReason?: string;
  
  // Rate limiting (leaky bucket)
  tokenBucket: {
    tokens: number;
    lastRefill: number;
    capacity: number;
    refillRate: number;
  };
  
  // Duplicate detection
  recentPacketHashes: {
    hash: string;
    timestamp: number;
    count: number;              // How many times this packet was seen
  }[];
  duplicateCount: number;       // Total duplicates seen (lifetime)
  duplicateRateWindow: {        // Track duplicate rate over time
    totalPackets: number;
    duplicatePackets: number;
    windowStart: number;
    windowMs: number;           // 5 minutes
  };
  
  // Counters (lifetime)
  totalPacketsReceived: number;
  totalPacketsSilenced: number;
  totalPacketsRelayed: number;
  
  // Behavioral metrics
  uniqueTopics: Set<string>;
  topicHistory: {
    topic: string;
    timestamp: number;
  }[];
  
  // IATA location tracking
  iataHistory: {
    iata: string;
    firstSeen: number;
    lastSeen: number;
  }[];
  currentIata?: string;
  iataChangeCount24h: number;
  
  // Clock tracking
  clockTracking: {
    version: number;                  // Schema version for clock tracking (increment to reset)
    estimatedOffset?: number;
    lastDeviceTimestamp?: number;
    lastBrokerTimestamp?: number;
    erraticJumps: {
      from: number;
      to: number;
      offsetChange: number;
      timestamp: number;
    }[];
  };
  
  // Anomaly tracking
  anomalyCount: number;
  anomalies: {
    type: string;
    details: string;
    timestamp: number;
  }[];
  
  // Performance/debugging
  lastPacketAt: number;
  avgPacketSize: number;
  peakRateObserved: number;
  peakRateWindow: {
    version: number;             // Schema version (v3 uses O(1) 1s buckets instead of timestamp array)
    packets: number[];           // Kept empty in v3 so SQLite saves stay compact
    windowMs: number;
  };
  // In-memory O(1) 1-second bucket ring buffer for 10s current rate calculation
  recentRateBuckets?: {
    epochs: Float64Array;
    counts: Uint16Array;
  };
}

export interface AbuseConfig {
  // Duplicate detection
  duplicateWindowSize: number;
  duplicateWindowMs: number;
  duplicateThreshold: number;
  maxDuplicatesPerPacket: number;    // Allow N copies of same packet (repeaters)
  duplicateRateThreshold: number;    // Max % of packets that can be duplicates (0-1)
  duplicateRateWindowMs: number;     // Window to measure duplicate rate (5 min)
  
  // Rate limiting
  bucketCapacity: number;
  bucketRefillRate: number;
  
  // Anomaly detection
  maxPacketSize: number;
  maxTopicsPerDay: number;
  anomalyThreshold: number;
  
  // IATA change detection
  maxIataChanges24h: number;
  
  // Topic tracking
  topicHistorySize: number;
  topicHistoryWindowMs: number;
  
  // Persistence
  persistencePath: string;
  persistenceIntervalMs: number;
  // Trust state is retained only for clients active within this window; older state is
  // evicted from memory and disk on each save so the store stays bounded by active clients.
  stateRetentionMs: number;

  // Enforcement & temporary timeout duration
  enforcementEnabled: boolean;
  muteDurationMs?: number;           // Temporary mute duration in ms (default: 4 hours = 14400000)
}

export interface FlaggedPublisherEntry {
  publicKeyPrefix: string;
  publicKey: string;
  currentIata?: string;
  status: 'allowed' | 'muted' | 'would_mute';
  muteReason?: string;
  mutedAt?: number;
  mutedUntil?: number;
  remainingMuteSeconds?: number;
  anomalyCount: number;
  duplicateCount: number;
  totalPacketsReceived: number;
  totalPacketsSilenced: number;
  peakRateObserved: number;
  lastPacketAt: number;
}

export interface AbuseDetectorSummary {
  enforcementEnabled: boolean;
  muteDurationSeconds: number;
  trackedPublishers: number;
  mutedPublishersCount: number;
  wouldMutePublishersCount: number;
  anomalousPublishersCount: number;
  totalPacketsReceived: number;
  totalPacketsSilenced: number;
  totalDuplicates: number;
  totalAnomalies: number;
  activeByIata1h: Record<string, {
    activePublishers1h: number;
    trackedPublishers: number;
    totalPacketsReceived: number;
  }>;
  flaggedPublishers: FlaggedPublisherEntry[];
  violators: FlaggedPublisherEntry[];
}

interface SerializedTrustState {
  publicKey: string;
  username: string;
  connectedAt: number;
  recentIPs: {
    ip: string;
    firstSeen: number;
    lastSeen: number;
    connectionCount: number;
  }[];
  status: 'allowed' | 'muted' | 'would_mute';
  mutedAt?: number;
  mutedUntil?: number;
  muteReason?: string;
  tokenBucket: {
    tokens: number;
    lastRefill: number;
    capacity: number;
    refillRate: number;
  };
  recentPacketHashes: {
    hash: string;
    timestamp: number;
    count: number;
  }[];
  duplicateCount: number;
  duplicateRateWindow: {
    totalPackets: number;
    duplicatePackets: number;
    windowStart: number;
    windowMs: number;
  };
  totalPacketsReceived: number;
  totalPacketsSilenced: number;
  totalPacketsRelayed: number;
  uniqueTopics: string[];
  topicHistory: { topic: string; timestamp: number }[];
  iataHistory: { iata: string; firstSeen: number; lastSeen: number }[];
  currentIata?: string;
  iataChangeCount24h: number;
  clockTracking: {
    version: number;
    estimatedOffset?: number;
    lastDeviceTimestamp?: number;
    lastBrokerTimestamp?: number;
    erraticJumps: { from: number; to: number; offsetChange: number; timestamp: number }[];
  };
  anomalyCount: number;
  anomalies: { type: string; details: string; timestamp: number }[];
  lastPacketAt: number;
  avgPacketSize: number;
  peakRateObserved: number;
  peakRateWindow: {
    version: number;
    packets: number[];
    windowMs: number;
  };
}

// ============================================================================
// Abuse Detector Class
// ============================================================================

export class AbuseDetector {
  private config: AbuseConfig;
  private muteDurationMs: number;
  private clients: Map<string, ClientTrustState> = new Map();
  private db: DatabaseSync;
  private persistenceInterval?: NodeJS.Timeout;
  
  // Global stats
  private stats = {
    totalClientsConnected: 0,
    totalClientsMuted: 0,
    totalPacketsSilenced: 0,
  };

  constructor(config: AbuseConfig) {
    this.config = config;
    this.muteDurationMs = config.muteDurationMs ?? DEFAULT_MUTE_DURATION_MS;
    
    // Initialize SQLite database
    this.db = new DatabaseSync(config.persistencePath);
    this.initDatabase();
    this.loadFromDatabase();
    
    // Start periodic persistence
    this.persistenceInterval = setInterval(() => {
      this.saveToDatabase();
    }, config.persistenceIntervalMs);
    if (this.persistenceInterval.unref) {
      this.persistenceInterval.unref();
    }
    
    console.log(`[ABUSE] Initialized with persistence at: ${config.persistencePath} (muteDuration: ${Math.round(this.muteDurationMs / 60000)}m)`);
  }

  private initDatabase(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS trust_states (
        public_key TEXT PRIMARY KEY,
        state_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
    
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_updated_at ON trust_states(updated_at)
    `);
  }

  private loadFromDatabase(): void {
    // Only load state for clients active within the retention window, and iterate rather than
    // materialising the whole table, so a large historical DB can never exhaust the heap on load.
    const now = Date.now();
    const cutoff = now - this.config.stateRetentionMs;
    const stmt = this.db.prepare('SELECT public_key, state_json FROM trust_states WHERE updated_at >= ?');

    let loaded = 0;
    for (const row of stmt.iterate(cutoff) as unknown as Iterable<{ public_key: string; state_json: string }>) {
      try {
        const serialized: SerializedTrustState = JSON.parse(row.state_json);
        const state = this.deserializeTrustState(serialized);
        this.checkAndExpireMute(state, now);
        this.clients.set(row.public_key, state);
        loaded++;

        if (state.status === 'muted') {
          this.stats.totalClientsMuted++;
        }
      } catch (error) {
        console.error(`[ABUSE] Failed to load trust state for ${row.public_key}:`, error);
      }
    }

    console.log(`[ABUSE] Loaded ${loaded} trust states from database`);
  }

  public saveToDatabase(): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO trust_states (public_key, state_json, updated_at)
      VALUES (?, ?, ?)
    `);

    const del = this.db.prepare('DELETE FROM trust_states WHERE public_key = ?');
    const sweep = this.db.prepare('DELETE FROM trust_states WHERE updated_at < ?');
    const now = Date.now();
    const cutoff = now - this.config.stateRetentionMs;
    let saved = 0;
    let evicted = 0;

    // Wrap all per-client writes in a single SQLite transaction so 200+ observers
    // commit in a single disk flush (< 5 ms) instead of 200 individual fsyncs.
    try {
      this.db.exec('BEGIN TRANSACTION');

      for (const [publicKey, state] of this.clients.entries()) {
        // Evict clients idle beyond the retention window from memory and disk so the store stays
        // bounded by active clients rather than every client ever seen.
        if (state.lastPacketAt < cutoff) {
          this.clients.delete(publicKey);
          del.run(publicKey);
          evicted++;
          continue;
        }
        try {
          this.checkAndExpireMute(state, now);
          const serialized = this.serializeTrustState(state);
          // Persist the client's real last-activity time as updated_at so retention (load filter
          // and the delete below) is driven by activity, not by when the row was last written.
          stmt.run(publicKey, JSON.stringify(serialized), state.lastPacketAt);
          saved++;
        } catch (error) {
          console.error(`[ABUSE] Failed to save trust state for ${publicKey}:`, error);
        }
      }

      // Sweep any orphaned rows for clients not currently tracked in memory (bounds disk).
      sweep.run(cutoff);

      this.db.exec('COMMIT');
    } catch (error) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Ignore rollback error
      }
      console.error('[ABUSE] Transaction failed while saving trust states:', error);
    }

    if (saved > 0 || evicted > 0) {
      console.log(`[ABUSE] Saved ${saved} trust states to database (evicted ${evicted} stale)`);
    }
  }

  private serializeTrustState(state: ClientTrustState): SerializedTrustState {
    return {
      publicKey: state.publicKey,
      username: state.username,
      connectedAt: state.connectedAt,
      recentIPs: state.recentIPs,
      status: state.status,
      mutedAt: state.mutedAt,
      mutedUntil: state.mutedUntil,
      muteReason: state.muteReason,
      tokenBucket: state.tokenBucket,
      recentPacketHashes: state.recentPacketHashes,
      duplicateCount: state.duplicateCount,
      duplicateRateWindow: state.duplicateRateWindow,
      totalPacketsReceived: state.totalPacketsReceived,
      totalPacketsSilenced: state.totalPacketsSilenced,
      totalPacketsRelayed: state.totalPacketsRelayed,
      uniqueTopics: Array.from(state.uniqueTopics),
      topicHistory: state.topicHistory,
      iataHistory: state.iataHistory,
      currentIata: state.currentIata,
      iataChangeCount24h: state.iataChangeCount24h,
      clockTracking: state.clockTracking,
      anomalyCount: state.anomalyCount,
      anomalies: state.anomalies,
      lastPacketAt: state.lastPacketAt,
      avgPacketSize: state.avgPacketSize,
      peakRateObserved: state.peakRateObserved,
      peakRateWindow: {
        version: 3,
        packets: [], // Do not persist per-packet timestamps in v3
        windowMs: RATE_WINDOW_MS,
      },
    };
  }

  private deserializeTrustState(serialized: SerializedTrustState): ClientTrustState {
    const state: ClientTrustState = {
      ...serialized,
      uniqueTopics: new Set(serialized.uniqueTopics),
      recentRateBuckets: {
        epochs: new Float64Array(RECENT_RATE_BUCKETS),
        counts: new Uint16Array(RECENT_RATE_BUCKETS),
      },
    };
    
    // Initialize duplicateRateWindow if missing
    if (!state.duplicateRateWindow) {
      state.duplicateRateWindow = {
        totalPackets: 0,
        duplicatePackets: 0,
        windowStart: Date.now(),
        windowMs: 300000, // 5 minutes
      };
    }
    
    // Initialize peakRateWindow if missing or upgrade v1/v2 -> v3 (drop persisted timestamp arrays)
    if (!state.peakRateWindow || !state.peakRateWindow.version || state.peakRateWindow.version < 1) {
      state.peakRateObserved = 0; // Reset bad old values
    }
    state.peakRateWindow = {
      version: 3,
      packets: [],
      windowMs: RATE_WINDOW_MS,
    };

    // Backfill mutedUntil for legacy muted states persisted before mutedUntil existed
    if ((state.status === 'muted' || state.status === 'would_mute') && !state.mutedUntil) {
      const baseTime = state.mutedAt || state.lastPacketAt || Date.now();
      state.mutedUntil = baseTime + this.muteDurationMs;
    }
    
    // Reset clock tracking if version is old or missing
    if (!state.clockTracking.version || state.clockTracking.version < 1) {
      state.clockTracking = {
        version: 1,
        erraticJumps: [],
      };
      state.anomalyCount = 0;
      state.anomalies = [];
    }

    // Trim anomaly logs persisted before the cap existed (multi-MB rows made
    // the synchronous save cycle stall the event loop)
    if (state.anomalies.length > MAX_STORED_ANOMALIES) {
      state.anomalies = state.anomalies.slice(-MAX_STORED_ANOMALIES);
    }

    return state;
  }

  public shutdown(): void {
    console.log('[ABUSE] Shutting down, saving final state...');
    this.saveToDatabase();
    
    if (this.persistenceInterval) {
      clearInterval(this.persistenceInterval);
    }
    
    this.db.close();
    console.log('[ABUSE] Shutdown complete');
  }

  // ============================================================================
  // Temporary Timeout (Mute) Lifecycle
  // ============================================================================

  /**
   * Check whether a client's temporary mute / would_mute timeout has expired,
   * and restore the client to 'allowed' with refreshed rate/anomaly windows.
   */
  public checkAndExpireMute(state: ClientTrustState, now: number = Date.now()): void {
    if (state.status !== 'muted' && state.status !== 'would_mute') {
      return;
    }

    const mutedUntil = state.mutedUntil ?? ((state.mutedAt ?? now) + this.muteDurationMs);
    state.mutedUntil = mutedUntil;

    if (now >= mutedUntil) {
      const prevStatus = state.status;
      if (prevStatus === 'muted' && this.stats.totalClientsMuted > 0) {
        this.stats.totalClientsMuted--;
      }

      state.status = 'allowed';
      state.mutedAt = undefined;
      state.mutedUntil = undefined;
      state.muteReason = undefined;

      // Reset token bucket and short-term anomaly/duplicate counters so the observer
      // is not immediately re-muted on its first packet after the timeout expires.
      state.tokenBucket.tokens = state.tokenBucket.capacity;
      state.tokenBucket.lastRefill = now;
      state.anomalyCount = 0;
      state.duplicateRateWindow.totalPackets = 0;
      state.duplicateRateWindow.duplicatePackets = 0;
      state.duplicateRateWindow.windowStart = now;

      console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] Temporary timeout expired (was ${prevStatus}), restored to allowed`);
    }
  }

  // ============================================================================
  // Client Management
  // ============================================================================

  public initializeClient(publicKey: string, username: string, clientIP?: string): void {
    const normalizedKey = publicKey.toUpperCase();
    if (this.clients.has(normalizedKey)) {
      const existing = this.clients.get(normalizedKey)!;
      this.checkAndExpireMute(existing, Date.now());
      console.log(`[ABUSE] [${normalizedKey.substring(0, 8)}] Client reconnected (status: ${existing.status})`);
      existing.connectedAt = Date.now();
      
      // Update IP tracking
      if (clientIP) {
        this.recordIP(existing, clientIP);
      }
      
      return;
    }

    const now = Date.now();
    const state: ClientTrustState = {
      publicKey: normalizedKey,
      username,
      connectedAt: now,
      recentIPs: [],
      status: 'allowed',
      tokenBucket: {
        tokens: this.config.bucketCapacity,
        lastRefill: now,
        capacity: this.config.bucketCapacity,
        refillRate: this.config.bucketRefillRate,
      },
      recentPacketHashes: [],
      duplicateCount: 0,
      duplicateRateWindow: {
        totalPackets: 0,
        duplicatePackets: 0,
        windowStart: now,
        windowMs: this.config.duplicateRateWindowMs,
      },
      totalPacketsReceived: 0,
      totalPacketsSilenced: 0,
      totalPacketsRelayed: 0,
      uniqueTopics: new Set(),
      topicHistory: [],
      iataHistory: [],
      iataChangeCount24h: 0,
      clockTracking: {
        version: 1,
        erraticJumps: [],
      },
      anomalyCount: 0,
      anomalies: [],
      lastPacketAt: now,
      avgPacketSize: 0,
      peakRateObserved: 0,
      peakRateWindow: {
        version: 3,
        packets: [],
        windowMs: RATE_WINDOW_MS,
      },
      recentRateBuckets: {
        epochs: new Float64Array(RECENT_RATE_BUCKETS),
        counts: new Uint16Array(RECENT_RATE_BUCKETS),
      },
    };

    this.clients.set(normalizedKey, state);
    this.stats.totalClientsConnected++;
    
    // Record initial IP
    if (clientIP) {
      this.recordIP(state, clientIP);
    }
    
    console.log(`[ABUSE] [${normalizedKey.substring(0, 8)}] Initialized trust tracking`);
  }

  private recordIP(state: ClientTrustState, ip: string): void {
    const now = Date.now();
    const existing = state.recentIPs.find(entry => entry.ip === ip);
    
    if (existing) {
      existing.lastSeen = now;
      existing.connectionCount++;
    } else {
      state.recentIPs.push({
        ip,
        firstSeen: now,
        lastSeen: now,
        connectionCount: 1,
      });
      
      // Keep only most recent 100 IPs
      if (state.recentIPs.length > 100) {
        // Sort by lastSeen desc and keep top 100
        state.recentIPs.sort((a, b) => b.lastSeen - a.lastSeen);
        state.recentIPs = state.recentIPs.slice(0, 100);
      }
    }
  }

  public getClientStats(publicKey: string): ClientTrustState | undefined {
    const state = this.clients.get(publicKey.toUpperCase());
    if (state) {
      this.checkAndExpireMute(state, Date.now());
    }
    return state;
  }

  /**
   * Compute a single-pass, memory-bounded summary of abuse detection and regional activity for $SYS telemetry
   */
  public getAllStats(maxFlagged: number = 25): AbuseDetectorSummary {
    const now = Date.now();
    const oneHourAgo = now - RATE_WINDOW_MS;
    let mutedPublishersCount = 0;
    let wouldMutePublishersCount = 0;
    let anomalousPublishersCount = 0;
    let totalPacketsReceived = 0;
    let totalPacketsSilenced = 0;
    let totalDuplicates = 0;
    let totalAnomalies = 0;

    const activeByIata1h: AbuseDetectorSummary['activeByIata1h'] = {};
    const flaggedCandidates: FlaggedPublisherEntry[] = [];
    const violators: FlaggedPublisherEntry[] = [];

    for (const state of this.clients.values()) {
      this.checkAndExpireMute(state, now);

      totalPacketsReceived += state.totalPacketsReceived;
      totalPacketsSilenced += state.totalPacketsSilenced;
      totalDuplicates += state.duplicateCount;
      totalAnomalies += state.anomalyCount;

      if (state.status === 'muted') {
        mutedPublishersCount++;
      } else if (state.status === 'would_mute') {
        wouldMutePublishersCount++;
      }

      if (state.anomalyCount > 0) {
        anomalousPublishersCount++;
      }

      if (state.currentIata) {
        let regionEntry = activeByIata1h[state.currentIata];
        if (!regionEntry) {
          regionEntry = { activePublishers1h: 0, trackedPublishers: 0, totalPacketsReceived: 0 };
          activeByIata1h[state.currentIata] = regionEntry;
        }
        regionEntry.trackedPublishers++;
        regionEntry.totalPacketsReceived += state.totalPacketsReceived;
        if (state.lastPacketAt >= oneHourAgo) {
          regionEntry.activePublishers1h++;
        }
      }

      if (state.status !== 'allowed' || state.anomalyCount > 0) {
        const remainingMuteSeconds =
          state.mutedUntil && state.mutedUntil > now
            ? Math.ceil((state.mutedUntil - now) / 1000)
            : undefined;

        const entry: FlaggedPublisherEntry = {
          publicKeyPrefix: state.publicKey.substring(0, 8),
          publicKey: state.publicKey,
          currentIata: state.currentIata,
          status: state.status,
          muteReason: state.muteReason,
          mutedAt: state.mutedAt,
          mutedUntil: state.mutedUntil,
          remainingMuteSeconds,
          anomalyCount: state.anomalyCount,
          duplicateCount: state.duplicateCount,
          totalPacketsReceived: state.totalPacketsReceived,
          totalPacketsSilenced: state.totalPacketsSilenced,
          peakRateObserved: Math.round(state.peakRateObserved * 100) / 100,
          lastPacketAt: state.lastPacketAt,
        };

        flaggedCandidates.push(entry);
        if (state.status === 'muted' || state.status === 'would_mute') {
          violators.push(entry);
        }
      }
    }

    flaggedCandidates.sort((a, b) => b.anomalyCount - a.anomalyCount || b.lastPacketAt - a.lastPacketAt);
    violators.sort((a, b) => (b.mutedAt || 0) - (a.mutedAt || 0) || b.lastPacketAt - a.lastPacketAt);

    return {
      enforcementEnabled: this.config.enforcementEnabled,
      muteDurationSeconds: Math.round(this.muteDurationMs / 1000),
      trackedPublishers: this.clients.size,
      mutedPublishersCount,
      wouldMutePublishersCount,
      anomalousPublishersCount,
      totalPacketsReceived,
      totalPacketsSilenced,
      totalDuplicates,
      totalAnomalies,
      activeByIata1h,
      flaggedPublishers: flaggedCandidates.slice(0, maxFlagged),
      violators: violators.slice(0, 100),
    };
  }

  // ============================================================================
  // Packet Processing
  // ============================================================================

  public recordPacket(clientOrKey: any, packet: any, parsedMessage?: any): boolean {
    const rawKey = typeof clientOrKey === 'string' ? clientOrKey : clientOrKey?.publicKey;
    if (!rawKey) {
      return false;
    }
    const publicKey = rawKey.toUpperCase();
    const state = this.clients.get(publicKey);
    
    if (!state) {
      console.error(`[ABUSE] No trust state for ${publicKey}`);
      return false;
    }

    const now = Date.now();
    this.checkAndExpireMute(state, now);

    // If client is currently muted (enforcement enabled and timeout active), silence immediately
    if (state.status === 'muted') {
      state.totalPacketsReceived++;
      state.totalPacketsSilenced++;
      this.stats.totalPacketsSilenced++;
      state.lastPacketAt = now;
      return false;
    }

    const prevLastPacketAt = state.lastPacketAt;
    state.totalPacketsReceived++;
    state.lastPacketAt = now;

    // Reset peak if no packets in last hour (O(1) decay check using prevLastPacketAt)
    if (prevLastPacketAt > 0 && now - prevLastPacketAt > RATE_WINDOW_MS) {
      state.peakRateObserved = 0;
    }

    // Update average packet size
    const payloadSize = packet.payload.length;
    if (state.avgPacketSize === 0) {
      state.avgPacketSize = payloadSize;
    } else {
      state.avgPacketSize = state.avgPacketSize * 0.9 + payloadSize * 0.1;
    }

    // O(1) 10-second rolling rate calculation using 1-second ring buffer buckets
    if (!state.recentRateBuckets) {
      state.recentRateBuckets = {
        epochs: new Float64Array(RECENT_RATE_BUCKETS),
        counts: new Uint16Array(RECENT_RATE_BUCKETS),
      };
    }
    const currentSec = Math.floor(now / 1000);
    const slot = currentSec % RECENT_RATE_BUCKETS;
    if (state.recentRateBuckets.epochs[slot] !== currentSec) {
      state.recentRateBuckets.epochs[slot] = currentSec;
      state.recentRateBuckets.counts[slot] = 1;
    } else {
      state.recentRateBuckets.counts[slot] += 1;
    }

    let recentPacketsCount = 0;
    for (let i = 0; i < RECENT_RATE_BUCKETS; i++) {
      const ageSec = currentSec - state.recentRateBuckets.epochs[i];
      if (ageSec >= 0 && ageSec < RECENT_RATE_BUCKETS) {
        recentPacketsCount += state.recentRateBuckets.counts[i];
      }
    }
    const currentRate = recentPacketsCount / RECENT_RATE_BUCKETS; // packets per second
    if (currentRate > state.peakRateObserved) {
      state.peakRateObserved = currentRate;
    }

    // Check packet size based on raw LoRa packet data (reuse parsedMessage if provided)
    try {
      const message = parsedMessage ?? packet?._parsedJson ?? JSON.parse(packet.payload.toString('utf-8'));
      if (message && message.raw) {
        // raw is hex string, so divide by 2 to get actual byte size
        const rawByteSize = message.raw.length / 2;
        
        // LoRa max packet size is ~255 bytes, anything beyond is suspicious
        if (rawByteSize > this.config.maxPacketSize) {
          console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Anomalous raw packet size: ${rawByteSize} bytes (hex: ${message.raw.length} chars)`);
          this.recordAnomaly(state, 'packet_size', `Raw packet size ${rawByteSize} bytes exceeds limit ${this.config.maxPacketSize}`);
        }
      }
    } catch {
      // If not JSON or no raw field, skip check
    }

    // Check rate limit
    if (!this.checkRateLimit(state)) {
      console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Rate limit exceeded`);
      this.muteClient(state, 'rate_limit_exceeded');
      if ((state.status as string) === 'muted') {
        state.totalPacketsSilenced++;
        this.stats.totalPacketsSilenced++;
        return false;
      }
      return true;
    }

    // Check for duplicates
    const payload = typeof packet.payload === 'string' ? packet.payload : packet.payload.toString('utf-8');
    if (!this.checkDuplicates(state, payload)) {
      console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Duplicate packet detected`);
      if ((state.status as string) === 'muted') {
        state.totalPacketsSilenced++;
        this.stats.totalPacketsSilenced++;
        return false;
      }
      return true;
    }

    if ((state.status as string) === 'muted') {
      state.totalPacketsSilenced++;
      this.stats.totalPacketsSilenced++;
      return false;
    }

    return true;
  }

  public shouldSilencePacket(clientOrKey: any): boolean {
    const rawKey = typeof clientOrKey === 'string' ? clientOrKey : clientOrKey?.publicKey;
    if (!rawKey) {
      return false;
    }
    const state = this.clients.get(rawKey.toUpperCase());
    if (!state) {
      return false;
    }

    this.checkAndExpireMute(state, Date.now());

    if (state.status === 'muted') {
      state.totalPacketsSilenced++;
      this.stats.totalPacketsSilenced++;
      return true;
    }

    return false;
  }

  // ============================================================================
  // Detection Methods
  // ============================================================================

  public checkDuplicates(state: ClientTrustState, payload: string): boolean {
    const hash = createHash('sha256').update(payload).digest('hex');
    const now = Date.now();

    // Clean old hashes (outside window)
    state.recentPacketHashes = state.recentPacketHashes.filter(
      item => now - item.timestamp < this.config.duplicateWindowMs
    );

    // Check if hash exists
    const existingHash = state.recentPacketHashes.find(item => item.hash === hash);
    
    // Reset duplicate rate window if expired
    if (now - state.duplicateRateWindow.windowStart > state.duplicateRateWindow.windowMs) {
      state.duplicateRateWindow.totalPackets = 0;
      state.duplicateRateWindow.duplicatePackets = 0;
      state.duplicateRateWindow.windowStart = now;
    }
    
    // Track total packets in window
    state.duplicateRateWindow.totalPackets++;
    
    if (existingHash) {
      existingHash.count++;
      existingHash.timestamp = now; // Update last seen
      state.duplicateCount++;
      state.duplicateRateWindow.duplicatePackets++;
      
      // Check 1: Too many copies of this specific packet
      if (existingHash.count > this.config.maxDuplicatesPerPacket) {
        this.recordAnomaly(
          state,
          'excessive_packet_copies',
          `Packet seen ${existingHash.count} times (max: ${this.config.maxDuplicatesPerPacket})`
        );
        
        if (state.anomalyCount >= this.config.anomalyThreshold) {
          this.muteClient(state, `anomaly_threshold_exceeded (${state.anomalyCount} anomalies)`);
        }
        
        return false; // Reject this copy
      }
      
      // Check 2: Overall duplicate rate too high
      if (state.duplicateRateWindow.totalPackets >= 20) { // Need at least 20 packets to judge
        const duplicateRate = state.duplicateRateWindow.duplicatePackets / state.duplicateRateWindow.totalPackets;
        
        if (duplicateRate > this.config.duplicateRateThreshold) {
          this.recordAnomaly(
            state,
            'high_duplicate_rate',
            `${Math.round(duplicateRate * 100)}% duplicates in last ${state.duplicateRateWindow.windowMs / 60000} min (max: ${this.config.duplicateRateThreshold * 100}%)`
          );
          
          if (state.anomalyCount >= this.config.anomalyThreshold) {
            this.muteClient(state, `anomaly_threshold_exceeded (${state.anomalyCount} anomalies)`);
          }
          
          return false;
        }
      }
      
      // Duplicate, but within acceptable limits
      return true;
    }

    // New unique packet - add to tracking
    state.recentPacketHashes.push({ hash, timestamp: now, count: 1 });
    
    // Limit size
    if (state.recentPacketHashes.length > this.config.duplicateWindowSize) {
      state.recentPacketHashes.shift();
    }

    return true;
  }

  public checkRateLimit(state: ClientTrustState): boolean {
    const now = Date.now();
    const timeSinceLastRefill = (now - state.tokenBucket.lastRefill) / 1000;
    
    // Refill tokens
    const tokensToAdd = timeSinceLastRefill * state.tokenBucket.refillRate;
    state.tokenBucket.tokens = Math.min(
      state.tokenBucket.capacity,
      state.tokenBucket.tokens + tokensToAdd
    );
    state.tokenBucket.lastRefill = now;

    // Check if we have tokens
    if (state.tokenBucket.tokens < 1) {
      return false;
    }

    // Consume token
    state.tokenBucket.tokens -= 1;
    return true;
  }

  public checkIataChange(state: ClientTrustState, iata: string): boolean {
    const now = Date.now();
    this.checkAndExpireMute(state, now);
    const twentyFourHoursAgo = now - 86400000;

    // Clean old history
    state.iataHistory = state.iataHistory.filter(
      item => item.lastSeen > twentyFourHoursAgo
    );

    // Check if this is a new IATA
    if (state.currentIata && state.currentIata !== iata) {
      const existingEntry = state.iataHistory.find(item => item.iata === iata);
      
      if (!existingEntry) {
        // New IATA
        state.iataChangeCount24h = state.iataHistory.length + 1;
        
        console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] IATA change detected (${state.currentIata} -> ${iata}, total: ${state.iataChangeCount24h}/${this.config.maxIataChanges24h} in 24h)`);
        
        if (state.iataChangeCount24h > this.config.maxIataChanges24h) {
          this.muteClient(state, `iata_changes_exceeded (${state.iataChangeCount24h} changes in 24h)`);
          return false;
        }
        
        state.iataHistory.push({
          iata,
          firstSeen: now,
          lastSeen: now,
        });
      } else {
        existingEntry.lastSeen = now;
      }
      
      state.currentIata = iata;
    } else if (!state.currentIata) {
      // First IATA
      state.currentIata = iata;
      state.iataHistory.push({
        iata,
        firstSeen: now,
        lastSeen: now,
      });
    } else {
      // Same IATA, update last seen
      const entry = state.iataHistory.find(item => item.iata === iata);
      if (entry) {
        entry.lastSeen = now;
      }
    }

    return true;
  }

  public checkAnomalies(state: ClientTrustState, packet: any): boolean {
    // Additional anomaly checks can be added here
    return true;
  }

  private recordAnomaly(state: ClientTrustState, type: string, details: string): void {
    state.anomalyCount++;
    state.anomalies.push({
      type,
      details,
      timestamp: Date.now(),
    });

    // Keep only the most recent entries - anomalyCount carries the total for
    // threshold checks, so the log is purely diagnostic
    if (state.anomalies.length > MAX_STORED_ANOMALIES) {
      state.anomalies.shift();
    }

    console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] Anomaly: ${type} - ${details}`);

    if (state.anomalyCount >= this.config.anomalyThreshold) {
      this.muteClient(state, `anomaly_threshold_exceeded (${state.anomalyCount} anomalies)`);
    }
  }

  public muteClient(state: ClientTrustState, reason: string): void {
    const now = Date.now();
    this.checkAndExpireMute(state, now);

    if (state.status === 'muted') {
      return;
    }

    const mutedUntil = now + this.muteDurationMs;
    const durationMin = Math.round(this.muteDurationMs / 60000);

    // Only actually mute if enforcement is enabled
    if (this.config.enforcementEnabled) {
      state.status = 'muted';
      state.mutedAt = now;
      state.mutedUntil = mutedUntil;
      state.muteReason = reason;
      this.stats.totalClientsMuted++;
      console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] MUTED for ${durationMin}m until ${new Date(mutedUntil).toISOString()} (reason: ${reason})`);
    } else {
      if (state.status !== 'would_mute') {
        state.status = 'would_mute';
        state.mutedAt = now;
        state.mutedUntil = mutedUntil;
        state.muteReason = reason;
      }
      console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] WOULD MUTE for ${durationMin}m (reason: ${reason}) [enforcement disabled]`);
    }
  }
}
