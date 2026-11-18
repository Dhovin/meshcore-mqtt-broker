/**
 * Rate limiting for failed connection and authentication attempts.
 * Separates pre-auth socket drops (IP-keyed with cooldown decay) from
 * credential failures (IP + IP:username keyed, only decayed by same-username success)
 * so an attacker cannot wipe admin login failures via observer/low-privilege logins.
 */

interface RateLimitRecord {
  count: number;
  firstFailure: number;
  blockedUntil?: number;
  lastDecayAt?: number;
}

export interface RateLimiterStats {
  trackedIPCount: number;
  blockedIPCount: number;
  totalBlocksIssued: number;
  totalBlockedAttempts: number;
  blockedIPs: {
    ip: string;
    failures: number;
    blockedUntil: number;
    remainingSeconds: number;
  }[];
}

export class RateLimiter {
  private failedConnectionsByIP = new Map<string, RateLimitRecord>();
  private authFailuresByIp = new Map<string, RateLimitRecord>();
  private authFailuresByIpUser = new Map<string, RateLimitRecord>();
  private readonly windowMs: number;
  private readonly maxFailedConnections: number;
  private readonly blockDurationMs: number;
  private readonly maxEntries: number;
  private readonly preAuthDecayCooldownMs: number;
  private cleanupInterval?: NodeJS.Timeout;
  private totalBlocksIssued = 0;
  private totalBlockedAttempts = 0;

  constructor(
    windowMs: number = 60000,               // 1 minute
    maxFailedConnections: number = 10,
    blockDurationMs: number = 300000,       // 5 minutes
    maxEntries: number = 10000,             // Bound map size to prevent memory exhaustion
    cleanupIntervalMs: number = 300000,     // Clean up expired records every 5 minutes
    preAuthDecayCooldownMs: number = 10000  // Min 10s between pre-auth drop decays per IP
  ) {
    this.windowMs = windowMs;
    this.maxFailedConnections = maxFailedConnections;
    this.blockDurationMs = blockDurationMs;
    this.maxEntries = maxEntries;
    this.preAuthDecayCooldownMs = preAuthDecayCooldownMs;

    if (cleanupIntervalMs > 0) {
      this.cleanupInterval = setInterval(() => {
        this.cleanupExpired();
      }, cleanupIntervalMs);
      // Unref interval so it does not keep the process alive
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref();
      }
    }
  }

  /**
   * Check whether a record's active block or failure tracking window has expired
   */
  private isRecordExpired(rec: RateLimitRecord, now: number): boolean {
    if (rec.blockedUntil) {
      return now >= rec.blockedUntil;
    }
    return now - rec.firstFailure > this.windowMs;
  }

  private pruneMap(map: Map<string, RateLimitRecord>, now: number): void {
    for (const [key, record] of map.entries()) {
      if (this.isRecordExpired(record, now)) {
        map.delete(key);
      }
    }
  }

  /**
   * Prune expired failure and block records from memory
   */
  public cleanupExpired(): void {
    const now = Date.now();
    this.pruneMap(this.failedConnectionsByIP, now);
    this.pruneMap(this.authFailuresByIp, now);
    this.pruneMap(this.authFailuresByIpUser, now);
  }

  /**
   * Evict an entry from a map to maintain capacity:
   * 1. Evict expired entries first.
   * 2. Evict the oldest unblocked entry.
   * 3. Never evict active blocks to make room.
   */
  private evictEntryFromMap(map: Map<string, RateLimitRecord>, now: number): boolean {
    for (const [key, rec] of map.entries()) {
      if (this.isRecordExpired(rec, now)) {
        map.delete(key);
        return true;
      }
    }

    for (const [key, rec] of map.entries()) {
      if (!rec.blockedUntil) {
        map.delete(key);
        return true;
      }
    }

    return false;
  }

  /**
   * Increment a counter record in the given map, enforcing capacity bounds and window expiration.
   */
  private incrementMapRecord(
    map: Map<string, RateLimitRecord>,
    key: string,
    now: number
  ): RateLimitRecord | null {
    const existing = map.get(key);

    if (!existing) {
      if (map.size >= this.maxEntries && !this.evictEntryFromMap(map, now)) {
        return null;
      }
      const created: RateLimitRecord = { count: 1, firstFailure: now };
      map.set(key, created);
      return created;
    }

    if (this.isRecordExpired(existing, now)) {
      map.delete(key);
      const reset: RateLimitRecord = { count: 1, firstFailure: now };
      map.set(key, reset);
      return reset;
    }

    existing.count++;
    // Refresh insertion order so recently active keys are kept over idle ones
    map.delete(key);
    map.set(key, existing);
    return existing;
  }

  private hasActiveBlockInMap(map: Map<string, RateLimitRecord>, key: string, now: number): boolean {
    const record = map.get(key);
    if (!record) return false;

    if (this.isRecordExpired(record, now)) {
      map.delete(key);
      return false;
    }

    return Boolean(record.blockedUntil && now < record.blockedUntil);
  }

  private hasActiveBlock(ip: string, now: number): boolean {
    return (
      this.hasActiveBlockInMap(this.failedConnectionsByIP, ip, now) ||
      this.hasActiveBlockInMap(this.authFailuresByIp, ip, now)
    );
  }

  private applyIpBlock(ip: string, record: RateLimitRecord, now: number, label: string): void {
    record.blockedUntil = now + this.blockDurationMs;
    this.totalBlocksIssued++;
    this.totalBlockedAttempts++;

    // Mirror active block into failedConnectionsByIP so getStats() reports all blocked IPs
    const dropRec = this.failedConnectionsByIP.get(ip);
    if (dropRec && !this.isRecordExpired(dropRec, now)) {
      dropRec.blockedUntil = record.blockedUntil;
      dropRec.count = Math.max(dropRec.count, record.count);
    } else if (
      this.failedConnectionsByIP.size < this.maxEntries ||
      this.evictEntryFromMap(this.failedConnectionsByIP, now)
    ) {
      this.failedConnectionsByIP.set(ip, {
        count: record.count,
        firstFailure: record.firstFailure,
        blockedUntil: record.blockedUntil,
      });
    }

    console.log(
      `[RATE_LIMIT] Blocking IP ${ip} for ${this.blockDurationMs / 1000}s ` +
      `(${record.count} ${label} in ${this.windowMs / 1000}s)`
    );
  }

  /**
   * Check if an IP address is currently blocked
   */
  isBlocked(ip: string, now: number = Date.now()): boolean {
    if (this.hasActiveBlock(ip, now)) {
      this.totalBlockedAttempts++;
      return true;
    }
    return false;
  }

  /**
   * Apply decay on successful authentication without allowing an attacker to wipe
   * failed password attempts for other accounts:
   * - Pre-auth socket drops decay by 1 at most once per preAuthDecayCooldownMs.
   * - Credential failures only decay by 1 when the exact same username authenticates.
   */
  recordSuccess(ip: string, username?: string, now: number = Date.now()): void {
    if (this.hasActiveBlock(ip, now)) {
      return;
    }

    // 1. Decay pre-auth socket drop count with cooldown
    const dropRec = this.failedConnectionsByIP.get(ip);
    if (dropRec && !dropRec.blockedUntil && !this.isRecordExpired(dropRec, now)) {
      if (
        dropRec.lastDecayAt === undefined ||
        now - dropRec.lastDecayAt >= this.preAuthDecayCooldownMs
      ) {
        dropRec.count = Math.max(0, dropRec.count - 1);
        dropRec.lastDecayAt = now;
      }
    }

    // 2. Decay same-username credential failure count only
    if (username) {
      const userKey = `${ip}:${username}`;
      const userRec = this.authFailuresByIpUser.get(userKey);
      if (userRec && !userRec.blockedUntil && !this.isRecordExpired(userRec, now) && userRec.count > 0) {
        userRec.count--;
        if (userRec.count === 0) {
          this.authFailuresByIpUser.delete(userKey);
        }

        const ipAuthRec = this.authFailuresByIp.get(ip);
        if (ipAuthRec && !ipAuthRec.blockedUntil && !this.isRecordExpired(ipAuthRec, now)) {
          ipAuthRec.count = Math.max(0, ipAuthRec.count - 1);
          if (ipAuthRec.count === 0) {
            this.authFailuresByIp.delete(ip);
          }
        }
      }
    }
  }

  /**
   * Record a failed pre-auth socket drop from an IP.
   * Returns true if the IP should now be blocked.
   */
  recordFailure(ip: string, now: number = Date.now()): boolean {
    const record = this.incrementMapRecord(this.failedConnectionsByIP, ip, now);
    if (!record) return false;

    if (record.count >= this.maxFailedConnections && !record.blockedUntil) {
      this.applyIpBlock(ip, record, now, 'failed connections');
      return true;
    }

    return false;
  }

  /**
   * Record a failed credential authentication attempt for an IP (and optionally username).
   * Returns true if the IP should now be blocked.
   */
  recordAuthFailure(ip: string, username?: string, now: number = Date.now()): boolean {
    if (username) {
      this.incrementMapRecord(this.authFailuresByIpUser, `${ip}:${username}`, now);
    }

    const record = this.incrementMapRecord(this.authFailuresByIp, ip, now);
    if (!record) return false;

    if (record.count >= this.maxFailedConnections && !record.blockedUntil) {
      this.applyIpBlock(ip, record, now, 'failed auth attempts');
      return true;
    }

    return false;
  }

  /**
   * Return a bounded snapshot of rate limiter metrics for $SYS telemetry
   */
  getStats(maxBlockedList: number = 50): RateLimiterStats {
    const now = Date.now();
    this.pruneMap(this.failedConnectionsByIP, now);
    this.pruneMap(this.authFailuresByIp, now);
    this.pruneMap(this.authFailuresByIpUser, now);

    const trackedIPs = new Set<string>();
    const blockedByIP = new Map<string, { failures: number; blockedUntil: number }>();

    for (const [ip, record] of this.failedConnectionsByIP.entries()) {
      if (record.count > 0 || record.blockedUntil) {
        trackedIPs.add(ip);
      }
      if (record.blockedUntil && now < record.blockedUntil) {
        blockedByIP.set(ip, { failures: record.count, blockedUntil: record.blockedUntil });
      }
    }

    for (const [ip, record] of this.authFailuresByIp.entries()) {
      if (record.count > 0 || record.blockedUntil) {
        trackedIPs.add(ip);
      }
      if (record.blockedUntil && now < record.blockedUntil && !blockedByIP.has(ip)) {
        blockedByIP.set(ip, { failures: record.count, blockedUntil: record.blockedUntil });
      }
    }

    const blockedIPs: RateLimiterStats['blockedIPs'] = [];
    for (const [ip, info] of blockedByIP.entries()) {
      if (blockedIPs.length >= maxBlockedList) break;
      blockedIPs.push({
        ip,
        failures: info.failures,
        blockedUntil: info.blockedUntil,
        remainingSeconds: Math.max(0, Math.ceil((info.blockedUntil - now) / 1000)),
      });
    }

    return {
      trackedIPCount: trackedIPs.size,
      blockedIPCount: blockedByIP.size,
      totalBlocksIssued: this.totalBlocksIssued,
      totalBlockedAttempts: this.totalBlockedAttempts,
      blockedIPs,
    };
  }

  /**
   * Total number of tracked IP records (for testing and metrics)
   */
  getRecordCount(): number {
    return this.failedConnectionsByIP.size;
  }

  /**
   * Clean up timer on broker shutdown
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
    this.failedConnectionsByIP.clear();
    this.authFailuresByIp.clear();
    this.authFailuresByIpUser.clear();
    this.totalBlocksIssued = 0;
    this.totalBlockedAttempts = 0;
  }
}
