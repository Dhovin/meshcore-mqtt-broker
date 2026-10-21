/**
 * Rate limiting for failed connection attempts by IP address
 * Includes bounded memory capacity and background cleanup of expired entries
 */

interface RateLimitRecord {
  count: number;
  firstFailure: number;
  blockedUntil?: number;
}

export class RateLimiter {
  private failedConnectionsByIP = new Map<string, RateLimitRecord>();
  private readonly windowMs: number;
  private readonly maxFailedConnections: number;
  private readonly blockDurationMs: number;
  private readonly maxEntries: number;
  private cleanupInterval?: NodeJS.Timeout;

  constructor(
    windowMs: number = 60000,        // 1 minute
    maxFailedConnections: number = 10,
    blockDurationMs: number = 300000, // 5 minutes
    maxEntries: number = 10000,      // Bound map size to prevent memory exhaustion
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
   * Prune expired failure and block records from memory
   */
  public cleanupExpired(): void {
    const now = Date.now();
    for (const [ip, record] of this.failedConnectionsByIP.entries()) {
      const isBlockExpired = !record.blockedUntil || now >= record.blockedUntil;
      const isWindowExpired = now - record.firstFailure > this.windowMs;

      if (isBlockExpired && isWindowExpired) {
        this.failedConnectionsByIP.delete(ip);
      }
    }
  }

  /**
   * Check if an IP address is currently blocked
   */
  isBlocked(ip: string): boolean {
    const record = this.failedConnectionsByIP.get(ip);
    if (!record) return false;

    if (record.blockedUntil && Date.now() < record.blockedUntil) {
      return true;
    }

    // Reset if window expired
    if (Date.now() - record.firstFailure > this.windowMs) {
      this.failedConnectionsByIP.delete(ip);
      return false;
    }

    return false;
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
        const oldestKey = this.failedConnectionsByIP.keys().next().value;
        if (oldestKey) {
          this.failedConnectionsByIP.delete(oldestKey);
        }
      }

      this.failedConnectionsByIP.set(ip, { count: 1, firstFailure: now });
      return false;
    }

    // Reset if window expired
    if (now - record.firstFailure > this.windowMs) {
      this.failedConnectionsByIP.set(ip, { count: 1, firstFailure: now });
      return false;
    }

    record.count++;

    // Block if threshold exceeded
    if (record.count >= this.maxFailedConnections && !record.blockedUntil) {
      record.blockedUntil = now + this.blockDurationMs;
      console.log(
        `[RATE_LIMIT] Blocking IP ${ip} for ${this.blockDurationMs / 1000}s ` +
        `(${record.count} failed connections in ${this.windowMs / 1000}s)`
      );
      return true;
    }

    return false;
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
  }
}
