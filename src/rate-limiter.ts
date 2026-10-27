/**
 * Rate limiting for failed connection attempts by IP address
 * Includes bounded memory capacity and background cleanup of expired entries
 */

interface RateLimitRecord {
  count: number;
  firstFailure: number;
  blockedUntil?: number;
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
  private readonly windowMs: number;
  private readonly maxFailedConnections: number;
  private readonly blockDurationMs: number;
  private readonly maxEntries: number;
  private cleanupInterval?: NodeJS.Timeout;
  private totalBlocksIssued = 0;
  private totalBlockedAttempts = 0;

  constructor(
    windowMs: number = 60000,          // 1 minute
    maxFailedConnections: number = 10,
    blockDurationMs: number = 300000,   // 5 minutes
    maxEntries: number = 10000,        // Bound map size to prevent memory exhaustion
    cleanupIntervalMs: number = 300000 // Clean up expired records every 5 minutes
  ) {
    this.windowMs = windowMs;
    this.maxFailedConnections = maxFailedConnections;
    this.blockDurationMs = blockDurationMs;
    this.maxEntries = maxEntries;

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

  /**
   * Prune expired failure and block records from memory
   */
  public cleanupExpired(): void {
    const now = Date.now();
    for (const [ip, record] of this.failedConnectionsByIP.entries()) {
      if (this.isRecordExpired(record, now)) {
        this.failedConnectionsByIP.delete(ip);
      }
    }
  }

  /**
   * Evict an entry to maintain capacity:
   * 1. Evict expired entries first.
   * 2. Evict the oldest unblocked entry.
   * 3. Never evict active blocks to make room.
   */
  private evictEntry(now: number): boolean {
    // 1. Evict expired entries first
    for (const [ip, rec] of this.failedConnectionsByIP.entries()) {
      if (this.isRecordExpired(rec, now)) {
        this.failedConnectionsByIP.delete(ip);
        return true;
      }
    }

    // 2. Evict oldest unblocked entry
    for (const [ip, rec] of this.failedConnectionsByIP.entries()) {
      if (!rec.blockedUntil) {
        this.failedConnectionsByIP.delete(ip);
        return true;
      }
    }

    // 3. Never evict active blocks to make room
    return false;
  }

  /**
   * Check if an IP address is currently blocked
   */
  isBlocked(ip: string): boolean {
    const record = this.failedConnectionsByIP.get(ip);
    if (!record) return false;

    const now = Date.now();
    if (this.isRecordExpired(record, now)) {
      this.failedConnectionsByIP.delete(ip);
      return false;
    }

    const isCurrentlyBlocked = Boolean(record.blockedUntil && now < record.blockedUntil);
    if (isCurrentlyBlocked) {
      this.totalBlockedAttempts++;
    }
    return isCurrentlyBlocked;
  }

  /**
   * Record a failed connection attempt from an IP
   * Returns true if the IP should now be blocked
   */
  recordFailure(ip: string): boolean {
    const now = Date.now();
    const record = this.failedConnectionsByIP.get(ip);

    if (!record) {
      // Enforce max capacity to prevent memory exhaustion attacks
      if (this.failedConnectionsByIP.size >= this.maxEntries) {
        const evicted = this.evictEntry(now);
        // If all entries are actively blocked, do not displace them
        if (!evicted) {
          return false;
        }
      }

      this.failedConnectionsByIP.set(ip, { count: 1, firstFailure: now });
      return false;
    }

    // Reset if previous window or block has expired
    if (this.isRecordExpired(record, now)) {
      this.failedConnectionsByIP.delete(ip);
      this.failedConnectionsByIP.set(ip, { count: 1, firstFailure: now });
      return false;
    }

    record.count++;

    // Refresh insertion order so recently failed IPs are kept over idle ones
    this.failedConnectionsByIP.delete(ip);
    this.failedConnectionsByIP.set(ip, record);

    // Block if threshold exceeded
    if (record.count >= this.maxFailedConnections && !record.blockedUntil) {
      record.blockedUntil = now + this.blockDurationMs;
      this.totalBlocksIssued++;
      this.totalBlockedAttempts++;
      console.log(
        `[RATE_LIMIT] Blocking IP ${ip} for ${this.blockDurationMs / 1000}s ` +
        `(${record.count} failed connections in ${this.windowMs / 1000}s)`
      );
      return true;
    }

    return false;
  }

  /**
   * Return a bounded snapshot of rate limiter metrics for $SYS telemetry
   */
  getStats(maxBlockedList: number = 50): RateLimiterStats {
    const now = Date.now();
    let blockedIPCount = 0;
    const blockedIPs: RateLimiterStats['blockedIPs'] = [];

    for (const [ip, record] of this.failedConnectionsByIP.entries()) {
      if (this.isRecordExpired(record, now)) {
        this.failedConnectionsByIP.delete(ip);
        continue;
      }
      if (record.blockedUntil && now < record.blockedUntil) {
        blockedIPCount++;
        if (blockedIPs.length < maxBlockedList) {
          blockedIPs.push({
            ip,
            failures: record.count,
            blockedUntil: record.blockedUntil,
            remainingSeconds: Math.max(0, Math.ceil((record.blockedUntil - now) / 1000)),
          });
        }
      }
    }

    return {
      trackedIPCount: this.failedConnectionsByIP.size,
      blockedIPCount,
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
    this.totalBlocksIssued = 0;
    this.totalBlockedAttempts = 0;
  }
}
